/* ieee802154_silabs_efr32.c - Silabs EFR32 802.15.4 driver */

/*
 * Copyright (c) 2026 Silicon Laboratories
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT silabs_efr32_ieee802154

#define LOG_MODULE_NAME ieee802154_silabs_efr32
#if defined(CONFIG_IEEE802154_SILABS_EFR32_DRIVER_LOG_LEVEL)
#define LOG_LEVEL CONFIG_IEEE802154_SILABS_EFR32_DRIVER_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_NONE
#endif

#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>
LOG_MODULE_REGISTER(LOG_MODULE_NAME);

#include <errno.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/clock.h>
#include <zephyr/device.h>
#include <zephyr/init.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>

#if defined(CONFIG_NET_L2_OPENTHREAD)
#include <zephyr/net/openthread.h>
#include <zephyr/net/ieee802154_radio_openthread.h>
#endif

#include <string.h>

#include <zephyr/devicetree.h>
#include <zephyr/net/ieee802154_radio.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/byteorder.h>

#include "ieee802154_silabs_efr32.h"

#if defined(_SILICON_LABS_32B_SERIES_2)
#include <em_system.h>
#else
#include <sl_hal_system.h>
#endif

#include <sl_rail.h>
#include <sl_rail_ieee802154.h>
#include "sl_rail_util_compatible_pa.h"

/* SiSDK PAL sequence: load_rail_config does config_2p4_ghz_radio then config TX power + set_tx_power_dbm;
 * we call sl_rail_util_pa_init() and set_tx_power(default). sl_rail_util_pa_post_init is not in
 * Simplicity SDK PA plugin; we apply 2.4 GHz PA config via sl_rail_config_tx_power + getter.
 */
extern void sl_rail_util_pa_init(void);

/* RAIL handle; init'd once in silabs_efr32_rail_init(). */
static sl_rail_handle_t s_rail_handle;
static bool s_rail_initialized;
/* Promiscuous mode requested before RAIL init (e.g. by OpenThread for active scan). */
static bool s_promiscuous_desired;

/* TX completion: errno to return from tx() (0, -ENOMSG, -EBUSY, -EIO). Set in events callback. */
static int s_tx_errno;

/* RAIL event bits (SiSDK may use SL_RAIL_* or RAIL_*; fallbacks from RAIL API docs). */
#if defined(SL_RAIL_EVENT_TX_PACKET_SENT)
#define SILABS_RAIL_EV_TX_SENT    SL_RAIL_EVENT_TX_PACKET_SENT
#elif defined(RAIL_EVENT_TX_PACKET_SENT)
#define SILABS_RAIL_EV_TX_SENT    RAIL_EVENT_TX_PACKET_SENT
#else
#define SILABS_RAIL_EV_TX_SENT    (1ULL << 24)
#endif
/* SiSDK uses RX_ACK_TIMEOUT for "ACK timeout while waiting for RX of ACK" after TX. */
#if defined(SL_RAIL_EVENT_RX_ACK_TIMEOUT)
#define SILABS_RAIL_EV_ACK_TIMEOUT  SL_RAIL_EVENT_RX_ACK_TIMEOUT
#elif defined(RAIL_EVENT_RX_ACK_TIMEOUT)
#define SILABS_RAIL_EV_ACK_TIMEOUT  RAIL_EVENT_RX_ACK_TIMEOUT
#else
#define SILABS_RAIL_EV_ACK_TIMEOUT  (1ULL << 1)
#endif
#if defined(SL_RAIL_EVENT_TX_CHANNEL_BUSY)
#define SILABS_RAIL_EV_TX_CHANNEL_BUSY  SL_RAIL_EVENT_TX_CHANNEL_BUSY
#elif defined(RAIL_EVENT_TX_CHANNEL_BUSY)
#define SILABS_RAIL_EV_TX_CHANNEL_BUSY  RAIL_EVENT_TX_CHANNEL_BUSY
#else
#define SILABS_RAIL_EV_TX_CHANNEL_BUSY  (1ULL << 26)
#endif
#if defined(SL_RAIL_EVENT_TX_ABORTED)
#define SILABS_RAIL_EV_TX_ABORTED  SL_RAIL_EVENT_TX_ABORTED
#elif defined(RAIL_EVENT_TX_ABORTED)
#define SILABS_RAIL_EV_TX_ABORTED  RAIL_EVENT_TX_ABORTED
#else
#define SILABS_RAIL_EV_TX_ABORTED  (1ULL << 26)
#endif
#if defined(SL_RAIL_EVENT_RX_PACKET_RECEIVED)
#define SILABS_RAIL_EV_RX_PKT    SL_RAIL_EVENT_RX_PACKET_RECEIVED
#elif defined(RAIL_EVENT_RX_PACKET_RECEIVED)
#define SILABS_RAIL_EV_RX_PKT    RAIL_EVENT_RX_PACKET_RECEIVED
#else
#define SILABS_RAIL_EV_RX_PKT    (1ULL << 3)
#endif
#if defined(SL_RAIL_EVENT_IEEE802154_DATA_REQUEST_COMMAND)
#define SILABS_RAIL_EV_DATA_REQUEST  SL_RAIL_EVENT_IEEE802154_DATA_REQUEST_COMMAND
#else
#define SILABS_RAIL_EV_DATA_REQUEST  (1ULL << 21)
#endif
/* For Zephyr IEEE802154_EVENT_TX_STARTED (host data/command TX started on air). */
#if defined(SL_RAIL_EVENT_TX_STARTED)
#define SILABS_RAIL_EV_TX_STARTED   SL_RAIL_EVENT_TX_STARTED
#elif defined(RAIL_EVENT_TX_STARTED)
#define SILABS_RAIL_EV_TX_STARTED   RAIL_EVENT_TX_STARTED
#else
#define SILABS_RAIL_EV_TX_STARTED   (1ULL << 36)
#endif
/* RX failure events -> IEEE802154_EVENT_RX_FAILED with ieee802154_rx_fail_reason. */
#if defined(SL_RAIL_EVENT_RX_FRAME_ERROR)
#define SILABS_RAIL_EV_RX_FRAME_ERROR    SL_RAIL_EVENT_RX_FRAME_ERROR
#else
#define SILABS_RAIL_EV_RX_FRAME_ERROR   (1ULL << 8)
#endif
#if defined(SL_RAIL_EVENT_RX_FIFO_OVERFLOW)
#define SILABS_RAIL_EV_RX_FIFO_OVERFLOW SL_RAIL_EVENT_RX_FIFO_OVERFLOW
#else
#define SILABS_RAIL_EV_RX_FIFO_OVERFLOW (1ULL << 10)
#endif
#if defined(SL_RAIL_EVENT_RX_PACKET_ABORTED)
#define SILABS_RAIL_EV_RX_PACKET_ABORTED SL_RAIL_EVENT_RX_PACKET_ABORTED
#else
#define SILABS_RAIL_EV_RX_PACKET_ABORTED (1ULL << 16)
#endif
#if defined(SL_RAIL_EVENT_RX_ADDRESS_FILTERED)
#define SILABS_RAIL_EV_RX_ADDRESS_FILTERED SL_RAIL_EVENT_RX_ADDRESS_FILTERED
#else
#define SILABS_RAIL_EV_RX_ADDRESS_FILTERED (1ULL << 11)
#endif

/*
 * Override RAIL assert handler so we log and halt instead of spinning forever.
 * The prebuilt RAIL library calls RAILCb_AssertFailed(handle, errorCode) on
 * failed assertions; the default implementation loops indefinitely.
 */
static const char *silabs_rail_assert_code_str(uint32_t code)
{
	switch (code) {
	case 0:  return "APPENDED_INFO_MISSING";
	case 1:  return "RX_FIFO_BYTES";
	case 4:  return "BAD_PACKET_LENGTH";
	case 6:  return "UNEXPECTED_STATE_RX_FIFO";
	case 7:  return "UNEXPECTED_STATE_RXLEN_FIFO";
	case 8:  return "UNEXPECTED_STATE_TX_FIFO";
	case 9:  return "UNEXPECTED_STATE_TXACK_FIFO";
	case 29: return "NULL_HANDLE";
	case 31: return "NO_ACTIVE_CONFIG";
	case 45: return "NULL_PARAMETER";
	case 62: return "FAILED_TX_CRC_CONFIG";
	case 63: return "INVALID_PA_OPERATION";
	case 64: return "SEQ_INVALID_PA_SELECTED";
	case 70: return "FAILED_MULTITIMER_CORRUPT";
	case 74: return "SECURE_ACCESS_FAULT";
	default: return NULL;
	}
}

void RAILCb_AssertFailed(void *rail_handle, uint32_t error_code)
{
	ARG_UNUSED(rail_handle);
	const char *code_str = silabs_rail_assert_code_str(error_code);

	if (code_str != NULL) {
		LOG_ERR("RAIL assert failed: %s (%u)", code_str, (unsigned int)error_code);
	} else {
		LOG_ERR("RAIL assert failed: error_code=%u (see RAIL_AssertErrorCodes_t)", (unsigned int)error_code);
	}
	log_flush();
	k_fatal_halt(K_ERR_CPU_EXCEPTION);
}

/* RX delivery work (run in thread context; ISR only schedules it). */
static void silabs_efr32_rx_work_handler(struct k_work *work);
static K_WORK_DEFINE(silabs_efr32_rx_work, silabs_efr32_rx_work_handler);

/* Event notification work: RAIL callback runs in ISR so we defer to thread. */
#define SILABS_EV_PENDING_TX_STARTED  (1U << 0)
#define SILABS_EV_PENDING_RX_FAILED   (1U << 1)
static atomic_t s_event_pending;
static enum ieee802154_rx_fail_reason s_rx_fail_reason;
static void silabs_efr32_event_work_handler(struct k_work *work);
static K_WORK_DEFINE(silabs_efr32_event_work, silabs_efr32_event_work_handler);
static const struct device *silabs_efr32_get_device(void);

/* Soft source match table (Thread: set Frame Pending in ACK for these addresses).
 * Add/clear via IEEE802154_CONFIG_ACK_FPB (otPlatRadioAddSrcMatch* / ClearSrcMatch*).
 * When SL_RAIL_EVENT_IEEE802154_DATA_REQUEST_COMMAND fires, we look up the source
 * address and call sl_rail_ieee802154_toggle_frame_pending() so the immediate ACK
 * has the FP bit set (SiSDK radio.cpp dataRequestCommandCallback).
 */
#define SILABS_SRC_MATCH_SHORT_MAX 16
#define SILABS_SRC_MATCH_EXT_MAX   16
static uint16_t s_src_match_short[SILABS_SRC_MATCH_SHORT_MAX];
static uint8_t  s_src_match_ext[SILABS_SRC_MATCH_EXT_MAX][8];
static uint8_t  s_src_match_short_count;
static uint8_t  s_src_match_ext_count;

/* Link-layer security: keys and frame counter (SiSDK radio_security / RAIL security).
 * Stored so that otPlatRadioSetMacKey / SetMacFrameCounter succeed. The stack
 * builds secured frames and passes them to tx(); we do not encrypt in the driver
 * unless RAIL security APIs are used. Key array is terminated by key_value == NULL.
 */
#define SILABS_SEC_KEY_SLOTS  3
#define IEEE802154_KEY_LEN   16
struct silabs_sec_key_entry {
	uint8_t  value[IEEE802154_KEY_LEN];
	uint8_t  key_id_mode;
	uint8_t  key_id;
	bool     frame_counter_per_key;
	uint32_t key_frame_counter;
};
static struct silabs_sec_key_entry s_sec_keys[SILABS_SEC_KEY_SLOTS];
static uint8_t  s_sec_key_count;
static uint32_t s_sec_global_frame_counter;

/* Driver data; defined here so the events callback can reference it. */
static struct silabs_efr32_802154_data silabs_efr32_data;

static bool src_match_short_contains(uint16_t short_addr);
static bool src_match_ext_contains(const uint8_t *addr);

/* RAIL events callback (runs in ISR). Minimal work: set TX result + give sem; schedule RX work. */
static void silabs_efr32_rail_events_callback(sl_rail_handle_t handle, sl_rail_events_t events)
{
	ARG_UNUSED(handle);

	/* TX completion: map RAIL events to errno and unblock tx(). */
	if ((events & SILABS_RAIL_EV_TX_SENT) != 0ULL) {
		s_tx_errno = 0;
		k_sem_give(&silabs_efr32_data.tx_wait);
		return;
	}
	if ((events & SILABS_RAIL_EV_ACK_TIMEOUT) != 0ULL) {
		s_tx_errno = -ENOMSG;
		k_sem_give(&silabs_efr32_data.tx_wait);
		return;
	}
	if ((events & SILABS_RAIL_EV_TX_CHANNEL_BUSY) != 0ULL) {
		s_tx_errno = -EBUSY;
		k_sem_give(&silabs_efr32_data.tx_wait);
		return;
	}
	if ((events & SILABS_RAIL_EV_TX_ABORTED) != 0ULL) {
		s_tx_errno = -EIO;
		k_sem_give(&silabs_efr32_data.tx_wait);
		return;
	}

	/* DATA_REQUEST_COMMAND: set Frame Pending in outgoing immediate ACK if source
	 * is in our soft source match table (SiSDK dataRequestCommandCallback).
	 */
	if ((events & SILABS_RAIL_EV_DATA_REQUEST) != 0ULL) {
		if (s_src_match_short_count > 0 || s_src_match_ext_count > 0) {
			sl_rail_ieee802154_address_t src_addr;

			if (sl_rail_ieee802154_get_address(handle, &src_addr) == SL_RAIL_STATUS_NO_ERROR) {
				bool match = false;

#if defined(SL_RAIL_IEEE802154_SHORT_ADDRESS) && defined(SL_RAIL_IEEE802154_LONG_ADDRESS)
				if (src_addr.address_length == SL_RAIL_IEEE802154_SHORT_ADDRESS) {
					match = src_match_short_contains(src_addr.short_address);
				} else if (src_addr.address_length == SL_RAIL_IEEE802154_LONG_ADDRESS) {
					match = src_match_ext_contains(src_addr.long_address);
				}
#else
				if (src_addr.address_length == 2) {
					match = src_match_short_contains(src_addr.short_address);
				} else if (src_addr.address_length == 8) {
					match = src_match_ext_contains(src_addr.long_address);
				}
#endif
				if (match) {
					(void)sl_rail_ieee802154_toggle_frame_pending(handle);
				}
			}
		}
	}

	/* RX: schedule work to read FIFO and deliver to net stack. */
	if ((events & SILABS_RAIL_EV_RX_PKT) != 0ULL) {
		k_work_submit(&silabs_efr32_rx_work);
	}

	/* Zephyr event notification: TX_STARTED (host data/command TX on air). */
	if ((events & SILABS_RAIL_EV_TX_STARTED) != 0ULL) {
		atomic_or(&s_event_pending, SILABS_EV_PENDING_TX_STARTED);
		k_work_submit(&silabs_efr32_event_work);
	}

	/* Zephyr event notification: RX_FAILED (map RAIL reason -> ieee802154_rx_fail_reason). */
	if ((events & (SILABS_RAIL_EV_RX_FRAME_ERROR | SILABS_RAIL_EV_RX_FIFO_OVERFLOW
		       | SILABS_RAIL_EV_RX_PACKET_ABORTED | SILABS_RAIL_EV_RX_ADDRESS_FILTERED)) != 0ULL) {
		if ((events & SILABS_RAIL_EV_RX_FRAME_ERROR) != 0ULL) {
			s_rx_fail_reason = IEEE802154_RX_FAIL_INVALID_FCS;
		} else if ((events & SILABS_RAIL_EV_RX_ADDRESS_FILTERED) != 0ULL) {
			s_rx_fail_reason = IEEE802154_RX_FAIL_ADDR_FILTERED;
		} else {
			s_rx_fail_reason = IEEE802154_RX_FAIL_OTHER;
		}
		atomic_or(&s_event_pending, SILABS_EV_PENDING_RX_FAILED);
		k_work_submit(&silabs_efr32_event_work);
	}
}

/* Run in thread context: deliver TX_STARTED / RX_FAILED to Zephyr event_handler. */
static void silabs_efr32_event_work_handler(struct k_work *work)
{
	uint32_t pending;
	const struct device *dev;
	struct silabs_efr32_802154_data *data;

	ARG_UNUSED(work);

	pending = (uint32_t)atomic_set(&s_event_pending, 0);
	if (pending == 0) {
		return;
	}
	dev = silabs_efr32_get_device();
	if (dev == NULL) {
		return;
	}
	data = (struct silabs_efr32_802154_data *)dev->data;
	if (data->event_handler == NULL) {
		return;
	}
	if ((pending & SILABS_EV_PENDING_TX_STARTED) != 0U) {
		data->event_handler(dev, IEEE802154_EVENT_TX_STARTED, NULL);
	}
	if ((pending & SILABS_EV_PENDING_RX_FAILED) != 0U) {
		data->event_handler(dev, IEEE802154_EVENT_RX_FAILED, (void *)&s_rx_fail_reason);
	}
}

/* IEEE 802.15.4 RAIL config (matches PAL sRailIeee802154Config). */
static const sl_rail_ieee802154_config_t s_rail_ieee802154_config = {
	.p_addresses = NULL,
	.ack_config = {
		.enable = true,
		.ack_timeout_us = 672,
		.rx_transitions = { .success = SL_RAIL_RF_STATE_RX, .error = SL_RAIL_RF_STATE_RX },
		.tx_transitions = { .success = SL_RAIL_RF_STATE_RX, .error = SL_RAIL_RF_STATE_RX },
	},
	.timings = {
		.idle_to_rx = 100,
		.tx_to_rx = 192 - 10,
		.idle_to_tx = 100,
		.rx_to_tx = 256,
		.rxsearch_timeout = 0,
		.tx_to_rxsearch_timeout = 0,
		.tx_to_tx = 0,
	},
	.frames_mask = SL_RAIL_IEEE802154_ACCEPT_STANDARD_FRAMES,
	.promiscuous_mode = false,
	.is_pan_coordinator = false,
	.default_frame_pending_in_outgoing_acks = false,
};

/* RAIL buffers: use SDK builtin for RX; provide our own TX FIFO (no builtin).
 * If sl_rail_init fails with INVALID_PARAMETER, init with minimal config (buffers
 * 0/NULL) and set RX/TX via sl_rail_set_* after init.
 */
#define SILABS_RAIL_RX_QUEUE_ENTRIES 16
#define SILABS_RAIL_RX_FIFO_BYTES   512
#define SILABS_RAIL_TX_FIFO_BYTES   256
static sl_rail_packet_queue_entry_t s_rail_rx_queue[SILABS_RAIL_RX_QUEUE_ENTRIES];
static sl_rail_fifo_buffer_align_t s_rail_rx_fifo[SILABS_RAIL_RX_FIFO_BYTES / sizeof(sl_rail_fifo_buffer_align_t)];
static sl_rail_fifo_buffer_align_t s_rail_tx_fifo[SILABS_RAIL_TX_FIFO_BYTES / sizeof(sl_rail_fifo_buffer_align_t)];

static int silabs_efr32_rail_init(void)
{
	sl_rail_status_t status;
	sl_rail_handle_t handle = SL_RAIL_EFR32_HANDLE;
	sl_rail_config_t rail_config = { 0 };

	rail_config.events_callback = silabs_efr32_rail_events_callback;
	/* Pass buffers at init (required by some RAIL builds). */
	rail_config.rx_packet_queue_entries = SILABS_RAIL_RX_QUEUE_ENTRIES;
	rail_config.p_rx_packet_queue = s_rail_rx_queue;
	rail_config.rx_fifo_bytes = SILABS_RAIL_RX_FIFO_BYTES;
	rail_config.p_rx_fifo_buffer = s_rail_rx_fifo;
	rail_config.tx_fifo_bytes = SILABS_RAIL_TX_FIFO_BYTES;
	rail_config.p_tx_fifo_buffer = s_rail_tx_fifo;
	rail_config.tx_fifo_init_bytes = 0U;

	/* Required before sl_rail_init() on Series 3; harmless on Series 2 (xG24). */
	(void)sl_rail_copy_device_info(SL_RAIL_EFR32_HANDLE);

	status = sl_rail_init(&handle, &rail_config, NULL);
	if (status != SL_RAIL_STATUS_NO_ERROR) {
		LOG_ERR("sl_rail_init failed: %d", (int)status);
		return -EIO;
	}
	status = sl_rail_config_cal(handle, SL_RAIL_CAL_ALL);
	if (status != SL_RAIL_STATUS_NO_ERROR) {
		LOG_ERR("sl_rail_config_cal failed: %d", (int)status);
		return -EIO;
	}
	status = sl_rail_set_pti_protocol(handle, SL_RAIL_PTI_PROTOCOL_THREAD);
	if (status != SL_RAIL_STATUS_NO_ERROR) {
		LOG_ERR("sl_rail_set_pti_protocol failed: %d", (int)status);
		return -EIO;
	}
	status = sl_rail_ieee802154_init(handle, &s_rail_ieee802154_config);
	if (status != SL_RAIL_STATUS_NO_ERROR) {
		LOG_ERR("sl_rail_ieee802154_init failed: %d", (int)status);
		return -EIO;
	}
#if defined(SL_RAIL_EVENT_IEEE802154_DATA_REQUEST_COMMAND)
	/* Deliver DATA_REQUEST_COMMAND so we can set FP in immediate ACK (SiSDK enable_early_frame_pending). */
	status = sl_rail_ieee802154_enable_early_frame_pending(handle, true);
	if (status != SL_RAIL_STATUS_NO_ERROR) {
		LOG_ERR("sl_rail_ieee802154_enable_early_frame_pending failed: %d", (int)status);
		return -EIO;
	}
	/* RAIL event mask must include SL_RAIL_EVENT_IEEE802154_DATA_REQUEST_COMMAND for this to run. */
#endif
#if defined(SL_RAIL_UTIL_IEEE802154_PHY_SELECT_PRESENT)
	status = sl_rail_util_ieee802154_config_radio(handle);
#else
	status = sl_rail_ieee802154_config_2p4_ghz_radio(handle);
#endif
	if (status != SL_RAIL_STATUS_NO_ERROR) {
		LOG_ERR("sl_rail_ieee802154_config_*_radio failed: %d", (int)status);
		return -EIO;
	}
	sl_rail_config_multi_timer(handle, true);

	/* Apply 2.4 GHz PA config (Simplicity SDK has no sl_rail_util_pa_post_init; use getter + config). */
	RAIL_TxPowerConfig_t *pa_cfg = sl_rail_util_pa_get_tx_power_config_2p4ghz();
	if (pa_cfg == NULL) {
		LOG_ERR("sl_rail_util_pa_get_tx_power_config_2p4ghz returned NULL");
		return -EIO;
	}
	status = sl_rail_config_tx_power(handle, pa_cfg);
	if (status != SL_RAIL_STATUS_NO_ERROR) {
		LOG_ERR("sl_rail_config_tx_power failed: %d", (int)status);
		return -EIO;
	}
	sl_rail_util_pa_init();
	/* SiSDK calls set_tx_power(OPENTHREAD_CONFIG_DEFAULT_TRANSMIT_POWER) after pa_init. */
	status = sl_rail_set_tx_power_dbm(handle, 0); /* 0 dBm initial; stack may set later */
	if (status != SL_RAIL_STATUS_NO_ERROR) {
		LOG_ERR("sl_rail_set_tx_power_dbm failed: %d", (int)status);
		return -EIO;
	}

	s_rail_handle = handle;
	s_rail_initialized = true;

	/* Apply promiscuous if it was requested before RAIL init (e.g. for active scan). */
	if (s_promiscuous_desired) {
		status = sl_rail_ieee802154_set_promiscuous_mode(handle, true);
		if (status != SL_RAIL_STATUS_NO_ERROR) {
			LOG_WRN("sl_rail_ieee802154_set_promiscuous_mode(true) failed: %d", (int)status);
		}
	}

	return 0;
}

#if DT_INST_NODE_HAS_PROP(0, hfxo)
#define SILABS_EFR32_HFXO_NODE DT_INST_PHANDLE(0, hfxo)
#define SILABS_EFR32_SCH_ACCURACY_PPM DT_PROP(SILABS_EFR32_HFXO_NODE, precision)
#else
#define SILABS_EFR32_SCH_ACCURACY_PPM 250
#endif

struct silabs_efr32_802154_config {
	void (*irq_config_func)(const struct device *dev);
};

#define SILABS_EFR32_802154_DATA(dev) \
	((struct silabs_efr32_802154_data * const)(dev)->data)

#define SILABS_EFR32_802154_CFG(dev) \
	((const struct silabs_efr32_802154_config * const)(dev)->config)

#if CONFIG_IEEE802154_VENDOR_OUI_ENABLE
#define IEEE802154_SILABS_EFR32_VENDOR_OUI CONFIG_IEEE802154_VENDOR_OUI
#else
#define IEEE802154_SILABS_EFR32_VENDOR_OUI (uint32_t)0xF4CE36
#endif

#if defined(CONFIG_IEEE802154_RAW_MODE)
static const struct device *silabs_efr32_dev;
#endif

static inline const struct device *silabs_efr32_get_device(void)
{
#if defined(CONFIG_IEEE802154_RAW_MODE)
	return silabs_efr32_dev;
#else
	return net_if_get_device(silabs_efr32_data.iface);
#endif
}

/* Driver-allocated attribute memory - constant across all driver instances.
 * Required for Part 1 (Confluence): IEEE802154_ATTR_PHY_SUPPORTED_CHANNEL_PAGES
 * and IEEE802154_ATTR_PHY_SUPPORTED_CHANNEL_RANGES; 2.4 GHz channels 11–26.
 */
#define SILABS_EFR32_CHANNEL_MIN 11
#define SILABS_EFR32_CHANNEL_MAX 26
IEEE802154_DEFINE_PHY_SUPPORTED_CHANNELS(silabs_efr32_drv_attr, SILABS_EFR32_CHANNEL_MIN, SILABS_EFR32_CHANNEL_MAX);

static int silabs_efr32_attr_get(const struct device *dev,
				  enum ieee802154_attr attr,
				  struct ieee802154_attr_value *value)
{
	ARG_UNUSED(dev);

	if (ieee802154_attr_get_channel_page_and_range(
		    attr, IEEE802154_ATTR_PHY_CHANNEL_PAGE_ZERO_OQPSK_2450_BPSK_868_915,
		    &silabs_efr32_drv_attr.phy_supported_channels, value) == 0) {
		return 0;
	}

	return -ENOENT;
}

static void silabs_efr32_irq_config(const struct device *dev)
{
	ARG_UNUSED(dev);
	/* RAIL IRQs are installed by rail_isr_installer() in soc_radio.c (soc_early_init_hook). */
}

/* Source match table helpers. config->ack_fpb.addr is little-endian. */
static int src_match_short_add(const uint8_t *addr_le)
{
	uint16_t a = sys_get_le16(addr_le);
	for (uint8_t i = 0; i < s_src_match_short_count; i++) {
		if (s_src_match_short[i] == a) {
			return 0; /* already present */
		}
	}
	if (s_src_match_short_count >= SILABS_SRC_MATCH_SHORT_MAX) {
		return -ENOMEM;
	}
	s_src_match_short[s_src_match_short_count++] = a;
	return 0;
}

static int src_match_short_remove(const uint8_t *addr_le)
{
	uint16_t a = sys_get_le16(addr_le);
	for (uint8_t i = 0; i < s_src_match_short_count; i++) {
		if (s_src_match_short[i] == a) {
			s_src_match_short[i] = s_src_match_short[--s_src_match_short_count];
			return 0;
		}
	}
	return -ENOENT;
}

static void src_match_short_clear(void)
{
	s_src_match_short_count = 0;
}

static int src_match_ext_add(const uint8_t *addr)
{
	for (uint8_t i = 0; i < s_src_match_ext_count; i++) {
		if (memcmp(s_src_match_ext[i], addr, 8) == 0) {
			return 0; /* already present */
		}
	}
	if (s_src_match_ext_count >= SILABS_SRC_MATCH_EXT_MAX) {
		return -ENOMEM;
	}
	memcpy(s_src_match_ext[s_src_match_ext_count++], addr, 8);
	return 0;
}

static int src_match_ext_remove(const uint8_t *addr)
{
	for (uint8_t i = 0; i < s_src_match_ext_count; i++) {
		if (memcmp(s_src_match_ext[i], addr, 8) == 0) {
			memcpy(s_src_match_ext[i], s_src_match_ext[s_src_match_ext_count - 1], 8);
			s_src_match_ext_count--;
			return 0;
		}
	}
	return -ENOENT;
}

static void src_match_ext_clear(void)
{
	s_src_match_ext_count = 0;
}

/* Used from DATA_REQUEST_COMMAND handler to decide if we set FP in the outgoing ACK. */
static bool src_match_short_contains(uint16_t short_addr)
{
	for (uint8_t i = 0; i < s_src_match_short_count; i++) {
		if (s_src_match_short[i] == short_addr) {
			return true;
		}
	}
	return false;
}

static bool src_match_ext_contains(const uint8_t *addr)
{
	for (uint8_t i = 0; i < s_src_match_ext_count; i++) {
		if (memcmp(s_src_match_ext[i], addr, 8) == 0) {
			return true;
		}
	}
	return false;
}

/* RX work: read one packet from RAIL and deliver to net stack (SiSDK get_rx_packet_info + copy_rx_packet). */
#define SILABS_EFR32_RX_BUF_SIZE (1 + IEEE802154_MAX_PHY_PACKET_SIZE)
static void silabs_efr32_rx_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	sl_rail_rx_packet_handle_t rx_handle;
	sl_rail_rx_packet_info_t rx_info;
	sl_rail_rx_packet_details_t rx_details;
	struct net_pkt *pkt;
	uint8_t rx_buf[SILABS_EFR32_RX_BUF_SIZE];
	uint16_t pkt_len = 0;
	int ret;

	if (!s_rail_initialized || silabs_efr32_data.iface == NULL) {
		return;
	}
	rx_handle = sl_rail_get_rx_packet_info(s_rail_handle, SL_RAIL_RX_PACKET_HANDLE_NEWEST,
					       &rx_info);
	if (rx_handle == SL_RAIL_RX_PACKET_HANDLE_INVALID || rx_info.packet_bytes == 0) {
		return;
	}
	if (rx_info.packet_bytes > SILABS_EFR32_RX_BUF_SIZE) {
		sl_rail_release_rx_packet(s_rail_handle, rx_handle);
		return;
	}
	if (sl_rail_copy_rx_packet(s_rail_handle, rx_buf, &rx_info) != SL_RAIL_STATUS_NO_ERROR) {
		sl_rail_release_rx_packet(s_rail_handle, rx_handle);
		return;
	}
	pkt_len = rx_info.packet_bytes;
	/* Get LQI and packet RSSI before releasing the packet. */
	if (sl_rail_get_rx_packet_details(s_rail_handle, rx_handle, &rx_details) != SL_RAIL_STATUS_NO_ERROR) {
		rx_details.lqi = 0;
		rx_details.rssi_dbm = SL_RAIL_RSSI_INVALID_DBM;
	}
	sl_rail_release_rx_packet(s_rail_handle, rx_handle);

	pkt = net_pkt_rx_alloc_with_buffer(silabs_efr32_data.iface, pkt_len,
					   NET_AF_UNSPEC, 0, K_NO_WAIT);
	if (pkt == NULL) {
		LOG_ERR("RX: no pkt");
		return;
	}
	if (net_pkt_write(pkt, rx_buf, pkt_len) < 0) {
		net_pkt_unref(pkt);
		return;
	}
	if (rx_details.rssi_dbm != SL_RAIL_RSSI_INVALID_DBM) {
		net_pkt_set_ieee802154_rssi_dbm(pkt, rx_details.rssi_dbm);
	} else {
		int16_t rssi = sl_rail_get_rssi(s_rail_handle, SL_RAIL_GET_RSSI_NO_WAIT);

		net_pkt_set_ieee802154_rssi_dbm(pkt, (int8_t)rssi);
	}
	net_pkt_set_ieee802154_lqi(pkt, rx_details.lqi);
	ret = net_recv_data(silabs_efr32_data.iface, pkt);
	if (ret < 0) {
		LOG_ERR("RX: net_recv_data %d", ret);
		net_pkt_unref(pkt);
	}
}

static void silabs_efr32_iface_init(struct net_if *iface)
{
	const struct device *dev = net_if_get_device(iface);
	struct silabs_efr32_802154_data *data = SILABS_EFR32_802154_DATA(dev);
	uint64_t eui64;

	data->iface = iface;

	/* EUI64 from platform unique ID (matches SiSDK otPlatRadioGetIeeeEui64). */
#if defined(_SILICON_LABS_32B_SERIES_2)
	eui64 = SYSTEM_GetUnique();
#else
	eui64 = sl_hal_system_get_unique();
#endif
	eui64 = sys_cpu_to_be64(eui64);
	memcpy(data->mac, &eui64, sizeof(data->mac));

	net_if_set_link_addr(iface, data->mac, sizeof(data->mac),
			    NET_LINK_IEEE802154);

	/* Call L2 init (e.g. OpenThread: openthread_l2_init -> platformRadioInit).
	 * Without this, net_if_up -> openthread_run -> ThreadNetif::Up() runs with
	 * radio_api still NULL and faults in otPlatRadioSleep. */
	ieee802154_init(iface);
}

static enum ieee802154_hw_caps silabs_efr32_get_capabilities(const struct device *dev)
{
	ARG_UNUSED(dev);
	/* Aligned with EFR32 PAL radio_interface.cpp sRadioCapabilities (otRadioCaps):
	 * ACK_TIMEOUT|CSMA_BACKOFF|ENERGY_SCAN|SLEEP_TO_TX|TRANSMIT_SEC|TRANSMIT_TIMING|
	 * RECEIVE_TIMING -> IEEE802154_HW_* equivalents. TX/RX/TX_SEC/ed_scan/start/stop
	 * implemented in medium/hard phase.
	 */
	return IEEE802154_HW_FCS | IEEE802154_HW_FILTER | IEEE802154_HW_TX_RX_ACK
	       | IEEE802154_HW_ENERGY_SCAN | IEEE802154_HW_SLEEP_TO_TX | IEEE802154_HW_CSMA
	       | IEEE802154_HW_TX_SEC | IEEE802154_HW_TXTIME | IEEE802154_HW_RXTIME;
}

static int silabs_efr32_cca(const struct device *dev)
{
	ARG_UNUSED(dev);
	/* EFR32 PAL does hardware CCA; this API is not supported (Confluence).
	 * When using RAIL: would map to sl_rail_get_rssi() vs CCA_THRESHOLD_DEFAULT.
	 */
	return -ENOTSUP;
}

static int silabs_efr32_set_channel(const struct device *dev, uint16_t channel)
{
	struct silabs_efr32_802154_data *data = SILABS_EFR32_802154_DATA(dev);

	if (channel < SILABS_EFR32_CHANNEL_MIN || channel > SILABS_EFR32_CHANNEL_MAX) {
		return -EINVAL;
	}
	data->current_channel = channel;
	/* Channel is applied on next start_rx (start() or after stop/start). */
	return 0;
}

static int silabs_efr32_filter(const struct device *dev, bool set,
			       enum ieee802154_filter_type type,
			       const struct ieee802154_filter *filter)
{
	struct silabs_efr32_802154_data *data = SILABS_EFR32_802154_DATA(dev);

	if (!set) {
		return -ENOTSUP;
	}
	if (filter == NULL) {
		return -EINVAL;
	}
	switch (type) {
	case IEEE802154_FILTER_TYPE_PAN_ID:
		data->pan_id = filter->pan_id;
		if (s_rail_initialized) {
			sl_rail_ieee802154_set_pan_id(s_rail_handle, filter->pan_id, 0);
		}
		break;
	case IEEE802154_FILTER_TYPE_SHORT_ADDR:
		data->short_addr = filter->short_addr;
		if (s_rail_initialized) {
			sl_rail_ieee802154_set_short_address(s_rail_handle, filter->short_addr, 0);
		}
		break;
	case IEEE802154_FILTER_TYPE_IEEE_ADDR:
		memcpy(data->ext_addr, filter->ieee_addr, sizeof(data->ext_addr));
		if (s_rail_initialized) {
			sl_rail_ieee802154_set_long_address(s_rail_handle, filter->ieee_addr, 0);
		}
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

static int silabs_efr32_set_txpower(const struct device *dev, int16_t dbm)
{
	ARG_UNUSED(dev);
	if (s_rail_initialized) {
		sl_rail_status_t status = sl_rail_set_tx_power_dbm(s_rail_handle, (sl_rail_tx_power_t)dbm * 10);
		if (status != SL_RAIL_STATUS_NO_ERROR) {
			return -EIO;
		}
	}
	return 0;
}

static int silabs_efr32_start(const struct device *dev)
{
	struct silabs_efr32_802154_data *data = SILABS_EFR32_802154_DATA(dev);

	if (s_rail_initialized) {
		/* Idle before start_rx so channel change (from set_channel) is applied. */
		sl_rail_idle(s_rail_handle, SL_RAIL_IDLE, true);
		sl_rail_scheduler_info_t bg_rx = {
			.priority = 255,
			.slip_time = 0,
			.transaction_time = 0,
		};
		sl_rail_status_t status = sl_rail_start_rx(s_rail_handle,
							   (uint8_t)data->current_channel,
							   &bg_rx);
		if (status != SL_RAIL_STATUS_NO_ERROR) {
			LOG_ERR("sl_rail_start_rx failed: %d", (int)status);
			return -EIO;
		}
	}
	return 0;
}

static int silabs_efr32_stop(const struct device *dev)
{
	ARG_UNUSED(dev);
	if (s_rail_initialized) {
		/* check if transmit is ongoing via sl_rail_get_radio_state */
		sl_rail_idle(s_rail_handle, SL_RAIL_IDLE, true);
	}
	return 0;
}

static int silabs_efr32_tx(const struct device *dev, enum ieee802154_tx_mode mode,
			   struct net_pkt *pkt, struct net_buf *frag)
{
	struct silabs_efr32_802154_data *data = SILABS_EFR32_802154_DATA(dev);
	uint8_t len;
	const uint8_t *payload;

	if (!s_rail_initialized) {
		return -ENOTSUP;
	}
	payload = frag->data;
	len = (uint8_t)frag->len;
	if (len > sizeof(data->tx_psdu) - 1) {
		return -EMSGSIZE;
	}
	/* PHR (first byte) = length; then MPDU */
	data->tx_psdu[0] = len;
	memcpy(&data->tx_psdu[1], payload, len);
	/* sl_rail_write_tx_fifo returns bytes written (0 = error), not sl_rail_status_t */
	uint16_t want = (uint16_t)(1 + len);
	uint16_t written = sl_rail_write_tx_fifo(s_rail_handle, data->tx_psdu, want, true);
	if (written != want) {
		/* Partial write usually means TX FIFO had leftover data; reset and retry once */
		if (written != 0U &&
		    sl_rail_reset_fifo(s_rail_handle, true, false) == SL_RAIL_STATUS_NO_ERROR) {
			written = sl_rail_write_tx_fifo(s_rail_handle, data->tx_psdu, want, true);
		}
		if (written != want) {
			LOG_ERR("sl_rail_write_tx_fifo wrote %u, expected %u", (unsigned int)written,
				(unsigned int)want);
			return -EIO;
		}
	}
	k_sem_reset(&data->tx_wait);
	s_tx_errno = -EIO; /* default if no event fires */
	{
		sl_rail_scheduler_info_t sch = { .priority = 0, .slip_time = 0, .transaction_time = 0 };
		sl_rail_tx_options_t opts = SL_RAIL_TX_OPTIONS_DEFAULT;
		sl_rail_status_t start_st;

		if (mode == IEEE802154_TX_MODE_CSMA_CA) {
			sl_rail_csma_config_t csma = SL_RAIL_CSMA_CONFIG_802_15_4_2003_2P4_GHZ_OQPSK_CSMA;

			start_st = sl_rail_start_cca_csma_tx(s_rail_handle,
							    (uint8_t)data->current_channel,
							    opts, &csma, &sch);
		} else {
			start_st = sl_rail_start_tx(s_rail_handle, (uint8_t)data->current_channel,
						   opts, &sch);
		}
		if (start_st != SL_RAIL_STATUS_NO_ERROR) {
			LOG_ERR("sl_rail_start_tx/cca_csma_tx failed: %d (channel %u)",
				(int)start_st, (unsigned int)data->current_channel);
			return -EIO;
		}
	}
	/* Block until RAIL events callback sets s_tx_errno and gives tx_wait. */
	k_sem_take(&data->tx_wait, K_FOREVER);
	(void)pkt;
	return s_tx_errno;
}

static void silabs_efr32_energy_scan_work(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(silabs_efr32_ed_scan_work, silabs_efr32_energy_scan_work);
static const struct device *s_ed_scan_dev;
static energy_scan_done_cb_t s_ed_scan_done_cb;
static uint16_t s_ed_scan_duration_ms;
static uint16_t s_ed_scan_elapsed;
static int16_t s_ed_scan_max_rssi;
#define SILABS_ED_SCAN_SAMPLE_MS 1
static void silabs_efr32_energy_scan_work(struct k_work *work)
{
	int16_t rssi;

	ARG_UNUSED(work);
	if (s_ed_scan_elapsed >= s_ed_scan_duration_ms) {
		if (s_ed_scan_done_cb && s_ed_scan_dev) {
			s_ed_scan_done_cb(s_ed_scan_dev, s_ed_scan_max_rssi);
		}
		return;
	}
	rssi = sl_rail_get_rssi(s_rail_handle, SL_RAIL_GET_RSSI_NO_WAIT);
	if (rssi != SL_RAIL_RSSI_INVALID_DBM && rssi > s_ed_scan_max_rssi) {
		s_ed_scan_max_rssi = rssi;
	}
	s_ed_scan_elapsed += SILABS_ED_SCAN_SAMPLE_MS;
	k_work_schedule(&silabs_efr32_ed_scan_work, K_MSEC(SILABS_ED_SCAN_SAMPLE_MS));
}

static int silabs_efr32_energy_scan_start(const struct device *dev, uint16_t duration,
					   energy_scan_done_cb_t done_cb)
{
	if (!s_rail_initialized || done_cb == NULL) {
		return -ENOTSUP;
	}
	s_ed_scan_dev = dev;
	s_ed_scan_done_cb = done_cb;
	s_ed_scan_duration_ms = duration;
	s_ed_scan_elapsed = 0;
	s_ed_scan_max_rssi = SL_RAIL_RSSI_INVALID_DBM;
	k_work_schedule(&silabs_efr32_ed_scan_work, K_MSEC(SILABS_ED_SCAN_SAMPLE_MS));
	return 0;
}

static net_time_t silabs_efr32_get_time(const struct device *dev)
{
	ARG_UNUSED(dev);
	if (!s_rail_initialized) {
		return -1;
	}
	/* Match SiSDK otPlatTimeGet() in alarm.c: RAIL time is 32-bit usec, extend to 64-bit
	 * with wrap counting. get_time returns nanoseconds (net_time_t).
	 */
	static uint32_t timer_wraps;
	static uint32_t prev_32_time_us;
	uint32_t now_32_us;
	uint64_t now_64_us;
	net_time_t result_ns;
	unsigned int key = irq_lock();
	now_32_us = sl_rail_get_time(s_rail_handle);
	if (now_32_us < prev_32_time_us) {
		timer_wraps++;
	}
	prev_32_time_us = now_32_us;
	now_64_us = ((uint64_t)timer_wraps << 32) + now_32_us;
	irq_unlock(key);
	result_ns = (net_time_t)(now_64_us * NSEC_PER_USEC);
	return result_ns;
}

static uint8_t silabs_efr32_get_acc(const struct device *dev)
{
	ARG_UNUSED(dev);
	/* CSL scheduler accuracy in ppm. When the board sets hfxo = &hfxo on the
	 * ieee802154 node, use the HFXO's precision (matches PAL SL_OPENTHREAD_HFXO_ACCURACY).
	 * Otherwise fall back to 250 ppm.
	 */
	return (uint8_t)SILABS_EFR32_SCH_ACCURACY_PPM;
}

static int silabs_efr32_configure(const struct device *dev,
				   enum ieee802154_config_type type,
				   const struct ieee802154_config *config)
{
	struct silabs_efr32_802154_data *data = SILABS_EFR32_802154_DATA(dev);
	sl_rail_status_t status;

	if (config == NULL) {
		return -EINVAL;
	}

	switch (type) {
	case IEEE802154_CONFIG_RX_ON_WHEN_IDLE:
		data->rx_on_when_idle = config->rx_on_when_idle;
		return 0;

	case IEEE802154_CONFIG_PROMISCUOUS:
		s_promiscuous_desired = config->promiscuous;
		if (!s_rail_initialized) {
			return 0;
		}
		status = sl_rail_ieee802154_set_promiscuous_mode(s_rail_handle,
								 config->promiscuous);
		return (status == SL_RAIL_STATUS_NO_ERROR) ? 0 : -EIO;

	case IEEE802154_CONFIG_PAN_COORDINATOR:
		/* SiSDK sets is_pan_coordinator only in sRailIeee802154Config at init.
		 * No runtime RAIL API found; store for future use / no-op.
		 */
		return 0;

	case IEEE802154_CONFIG_AUTO_ACK_FPB:
		/* SiSDK: otPlatRadioEnableSrcMatch(aEnable) sets frame pending for
		 * all outgoing ACKs when aEnable is false. RAIL default is
		 * default_frame_pending_in_outgoing_acks; no runtime API in use here.
		 */
		return 0;

	case IEEE802154_CONFIG_ACK_FPB:
		/* Soft source match table (SiSDK soft_source_table_match / AddSrcMatch*). */
		if (config->ack_fpb.enabled) {
			if (config->ack_fpb.addr == NULL) {
				return -EINVAL;
			}
			if (config->ack_fpb.extended) {
				return src_match_ext_add(config->ack_fpb.addr);
			} else {
				return src_match_short_add(config->ack_fpb.addr);
			}
		}
		if (config->ack_fpb.addr != NULL) {
			if (config->ack_fpb.extended) {
				return src_match_ext_remove(config->ack_fpb.addr);
			} else {
				return src_match_short_remove(config->ack_fpb.addr);
			}
		}
		if (config->ack_fpb.extended) {
			src_match_ext_clear();
		} else {
			src_match_short_clear();
		}
		return 0;

	case IEEE802154_CONFIG_EVENT_HANDLER:
		/* event_handler is invoked from silabs_efr32_event_work_handler for
		 * IEEE802154_EVENT_TX_STARTED (RAIL TX_STARTED) and IEEE802154_EVENT_RX_FAILED
		 * (RAIL RX_FRAME_ERROR / RX_FIFO_OVERFLOW / RX_PACKET_ABORTED / RX_ADDRESS_FILTERED).
		 * IEEE802154_EVENT_RX_OFF is not supported (CSL-only).
		 */
		data->event_handler = config->event_handler;
		return 0;

	case IEEE802154_CONFIG_MAC_KEYS: {
		struct ieee802154_key *in = config->mac_keys;

		if (in == NULL) {
			return -EINVAL;
		}
		s_sec_key_count = 0;
		if (in->key_value == NULL) {
			/* Clear all keys (e.g. OpenThread stack reset). */
			return 0;
		}
		for (; in->key_value != NULL && s_sec_key_count < SILABS_SEC_KEY_SLOTS; in++) {
			memcpy(s_sec_keys[s_sec_key_count].value, in->key_value, IEEE802154_KEY_LEN);
			s_sec_keys[s_sec_key_count].key_id_mode = in->key_id_mode;
			s_sec_keys[s_sec_key_count].key_id =
				(in->key_id != NULL) ? *in->key_id : 0U;
			s_sec_keys[s_sec_key_count].frame_counter_per_key = in->frame_counter_per_key;
			s_sec_keys[s_sec_key_count].key_frame_counter = in->key_frame_counter;
			s_sec_key_count++;
		}
		return 0;
	}

	case IEEE802154_CONFIG_FRAME_COUNTER:
		if (config->frame_counter <= s_sec_global_frame_counter) {
			return -EINVAL;
		}
		s_sec_global_frame_counter = config->frame_counter;
		return 0;

	case IEEE802154_CONFIG_FRAME_COUNTER_IF_LARGER:
		if (config->frame_counter > s_sec_global_frame_counter) {
			s_sec_global_frame_counter = config->frame_counter;
		}
		return 0;

	case IEEE802154_CONFIG_RX_SLOT:
	case IEEE802154_CONFIG_CSL_PERIOD:
	case IEEE802154_CONFIG_EXPECTED_RX_TIME:
	case IEEE802154_CONFIG_ENH_ACK_HEADER_IE:
		/* Scheduled RX / CSL / enhanced ACK IE: TODO when needed. */
		return -ENOTSUP;

	default:
		return -ENOTSUP;
	}
}

#if defined(CONFIG_IEEE802154_CARRIER_FUNCTIONS)
static int silabs_efr32_continuous_carrier(const struct device *dev)
{
	ARG_UNUSED(dev);
	return -ENOTSUP;
}

static int silabs_efr32_modulated_carrier(const struct device *dev, const uint8_t *data)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(data);
	return -ENOTSUP;
}
#endif

static const struct silabs_efr32_802154_config silabs_efr32_radio_cfg = {
	.irq_config_func = silabs_efr32_irq_config,
};

static const struct ieee802154_radio_api silabs_efr32_radio_api = {
	.iface_api.init = silabs_efr32_iface_init,

	.get_capabilities = silabs_efr32_get_capabilities,
	.cca = silabs_efr32_cca,
	.set_channel = silabs_efr32_set_channel,
	.filter = silabs_efr32_filter,
	.set_txpower = silabs_efr32_set_txpower,
	.start = silabs_efr32_start,
	.stop = silabs_efr32_stop,
	.tx = silabs_efr32_tx,
	.ed_scan = silabs_efr32_energy_scan_start,
	.get_time = silabs_efr32_get_time,
	.get_sch_acc = silabs_efr32_get_acc,
	.configure = silabs_efr32_configure,
	.attr_get = silabs_efr32_attr_get,
#if defined(CONFIG_IEEE802154_CARRIER_FUNCTIONS)
	.continuous_carrier = silabs_efr32_continuous_carrier,
	.modulated_carrier = silabs_efr32_modulated_carrier,
#endif
};

static int silabs_efr32_init(const struct device *dev)
{
	const struct silabs_efr32_802154_config *cfg = SILABS_EFR32_802154_CFG(dev);
	struct silabs_efr32_802154_data *data = SILABS_EFR32_802154_DATA(dev);

	k_sem_init(&data->cca_wait, 0, 1);
	k_sem_init(&data->tx_wait, 0, 1);

	if (cfg->irq_config_func != NULL) {
		cfg->irq_config_func(dev);
	}

	{
		int r = silabs_efr32_rail_init();

		if (r != 0) {
			return r;
		}
	}

#if defined(CONFIG_IEEE802154_RAW_MODE)
	silabs_efr32_dev = dev;
#endif

	return 0;
}

#if defined(CONFIG_NET_L2_IEEE802154)
#define L2 IEEE802154_L2
#define L2_CTX_TYPE NET_L2_GET_CTX_TYPE(IEEE802154_L2)
#define MTU IEEE802154_MTU
#elif defined(CONFIG_NET_L2_OPENTHREAD)
#define L2 OPENTHREAD_L2
#define L2_CTX_TYPE NET_L2_GET_CTX_TYPE(OPENTHREAD_L2)
#define MTU 1280
#elif defined(CONFIG_NET_L2_CUSTOM_IEEE802154)
#define L2 CUSTOM_IEEE802154_L2
#define L2_CTX_TYPE NET_L2_GET_CTX_TYPE(CUSTOM_IEEE802154_L2)
#define MTU CONFIG_NET_L2_CUSTOM_IEEE802154_MTU
#endif

#if defined(CONFIG_NET_L2_PHY_IEEE802154)
NET_DEVICE_DT_INST_DEFINE(0, silabs_efr32_init, NULL,
			  &silabs_efr32_data, &silabs_efr32_radio_cfg,
			  CONFIG_IEEE802154_SILABS_EFR32_INIT_PRIO,
			  &silabs_efr32_radio_api, L2, L2_CTX_TYPE, MTU);
#else
DEVICE_DT_INST_DEFINE(0, silabs_efr32_init, NULL,
		     &silabs_efr32_data, &silabs_efr32_radio_cfg,
		     POST_KERNEL, CONFIG_IEEE802154_SILABS_EFR32_INIT_PRIO,
		     &silabs_efr32_radio_api);
#endif

/* ieee802154_silabs_efr32.h - Silabs EFR32 802.15.4 driver */

/*
 * Copyright (c) 2026 Silicon Laboratories
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_IEEE802154_IEEE802154_SILABS_EFR32_H_
#define ZEPHYR_DRIVERS_IEEE802154_IEEE802154_SILABS_EFR32_H_

#include <zephyr/net/ieee802154_radio.h>

struct silabs_efr32_802154_data {
	/* Pointer to the network interface. */
	struct net_if *iface;

	/* 802.15.4 HW address. */
	uint8_t mac[8];

	/* Current channel (11–26 for 2.4 GHz O-QPSK). Set by set_channel(). */
	uint16_t current_channel;

	/* Filter state (maps to otPlatRadioSet* in PAL). Applied by filter(). */
	uint16_t pan_id;
	uint16_t short_addr;
	uint8_t ext_addr[8];

	/* CCA complete semaphore. Unlocked when CCA is complete. */
	struct k_sem cca_wait;

	/* CCA result. Holds information whether channel is free or not. */
	bool channel_free;

	/* TX synchronization semaphore. Unlocked when frame has been
	 * sent or send procedure failed.
	 */
	struct k_sem tx_wait;

	/* TX buffer. First byte is PHR (length), remaining bytes are
	 * MPDU data.
	 */
	uint8_t tx_psdu[1 + IEEE802154_MAX_PHY_PACKET_SIZE];

	/* TX result, updated in radio transmit callbacks. */
	uint8_t tx_result;

	/* Callback handler of the currently ongoing energy scan.
	 * It shall be NULL if energy scan is not in progress.
	 */
	energy_scan_done_cb_t energy_scan_done;

	/* Callback handler to notify of any important radio events.
	 * Can be NULL if event notification is not needed.
	 */
	ieee802154_event_cb_t event_handler;

	/* Capabilities of the network interface. */
	enum ieee802154_hw_caps capabilities;

	/* Indicates if currently processed TX frame is secured. */
	bool tx_frame_is_secured;

	/* Indicates if currently processed TX frame has dynamic data updated. */
	bool tx_frame_mac_hdr_rdy;

	/* The TX power in dBm. */
	int8_t txpwr;

	/* Indicates if RxOnWhenIdle mode is enabled. */
	bool rx_on_when_idle;
};

#endif /* ZEPHYR_DRIVERS_IEEE802154_IEEE802154_SILABS_EFR32_H_ */

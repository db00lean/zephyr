/*
 * Copyright (c) 2016 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief IEEE 802.15.4 MAC frame related functions
 *
 * @details This is not to be included by the application.
 *
 * @note All references to the standard in this file cite IEEE 802.15.4-2020.
 *
 * @note All structs and attributes (e.g. PAN id, ext address and short address)
 * in this file that directly represent parts of IEEE 802.15.4 frames are in
 * LITTLE ENDIAN, see section 4, especially section 4.3.
 */

#ifndef __IEEE802154_FRAME_H__
#define __IEEE802154_FRAME_H__

#include <zephyr/kernel.h>
#include <zephyr/net/ieee802154.h>
#include <zephyr/net/ieee802154_mac.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/toolchain.h>

#ifdef CONFIG_NET_L2_IEEE802154_SECURITY
struct ieee802154_aux_security_hdr *
ieee802154_validate_aux_security_hdr(uint8_t *buf, uint8_t **p_buf, uint8_t *length);
#endif

struct ieee802154_fcf_seq *ieee802154_validate_fc_seq(uint8_t *buf, uint8_t **p_buf,
						      uint8_t *length);

/**
 * @brief Calculate the beacon header length.
 *
 * @details Returns the length of the MAC payload without the beacon payload,
 * see section 7.3.1.1, figure 7-5.
 *
 * @param buf pointer to the MAC payload
 * @param length buffer length
 *
 * @retval -EINVAL The header is invalid.
 * @return the length of the beacon header
 */
int ieee802514_beacon_header_length(uint8_t *buf, uint8_t length);

bool ieee802154_validate_frame(uint8_t *buf, uint8_t length, struct ieee802154_mpdu *mpdu);

void ieee802154_compute_header_and_authtag_len(struct net_if *iface, struct net_linkaddr *dst,
					       struct net_linkaddr *src, uint8_t *ll_hdr_len,
					       uint8_t *authtag_len);

bool ieee802154_create_data_frame(struct ieee802154_context *ctx, struct net_linkaddr *dst,
				  struct net_linkaddr *src, struct net_buf *buf,
				  uint8_t ll_hdr_len);

struct net_pkt *ieee802154_create_mac_cmd_frame(struct net_if *iface, enum ieee802154_cfi type,
						struct ieee802154_frame_params *params);

void ieee802154_mac_cmd_finalize(struct net_pkt *pkt, enum ieee802154_cfi type);

static inline struct ieee802154_command *ieee802154_get_mac_command(struct net_pkt *pkt)
{
	return (struct ieee802154_command *)(pkt->frags->data + pkt->frags->len);
}

bool ieee802154_create_ack_frame(struct net_if *iface, struct net_pkt *pkt, uint8_t seq);

#ifdef CONFIG_NET_L2_IEEE802154_SECURITY
bool ieee802154_decipher_data_frame(struct net_if *iface, struct net_pkt *pkt,
				    struct ieee802154_mpdu *mpdu);
#else
#define ieee802154_decipher_data_frame(...) true
#endif /* CONFIG_NET_L2_IEEE802154_SECURITY */

#endif /* __IEEE802154_FRAME_H__ */

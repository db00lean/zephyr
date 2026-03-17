/* ieee802154_silabs_packet_utils.h - Silabs EFR32 802.15.4 packet utilities */

/*
 * Copyright (c) 2026 Silicon Laboratories
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IEEE802154_SILABS_PACKET_UTILS_H_
#define IEEE802154_SILABS_PACKET_UTILS_H_

#include <stdbool.h>
#include <stdint.h>

#define SILABS_CCM_NONCE_SIZE 13

/**
 * Build AES-CCM nonce from extended address, frame counter and security level (per 802.15.4).
 */
void silabs_generate_nonce(const uint8_t *ext_address, uint32_t frame_counter,
			   uint8_t security_level, uint8_t *nonce);

/**
 * Run AES-CCM on an MPDU (encrypt payload, compute MIC). Caller must have set frame counter
 * and key index in the aux security header. Nonce must be from silabs_generate_nonce.
 *
 * @param mpdu           MPDU (modified in place: payload + footer).
 * @param mpdu_len       Total MPDU length in bytes.
 * @param header_length  MHR length including aux sec.
 * @param security_level 0-7 (determines MIC length and whether payload is encrypted).
 * @param key            AES-128 key (16 bytes).
 * @param nonce          Nonce (SILABS_CCM_NONCE_SIZE bytes).
 * @return true on success, false on CCM error.
 */
bool silabs_tx_ccm(uint8_t *mpdu, uint16_t mpdu_len, uint8_t header_length,
		   uint8_t security_level, const uint8_t *key, const uint8_t *nonce);

#endif /* IEEE802154_SILABS_PACKET_UTILS_H_ */

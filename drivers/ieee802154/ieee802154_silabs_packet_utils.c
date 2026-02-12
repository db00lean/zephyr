/* ieee802154_silabs_packet_utils.c - Silabs EFR32 802.15.4 packet utilities */

/*
 * Copyright (c) 2026 Silicon Laboratories
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openthread-core-zephyr-config.h>

#include "em_device.h"
#include "ieee802154_silabs_packet_utils.h"
#include "sl_core.h"
#include "zephyr/net/ieee802154.h"
#include "zephyr/sys/byteorder.h"
#if defined(RADIOAES_PRESENT)
#include "sli_protocol_crypto.h"
#else
#include "sli_crypto.h"
#endif

#if defined(LPWAES_PRESENT) && defined(KSU_PRESENT)
#include "security_manager.h"
#include "sl_se_manager.h"
#include "sl_se_manager_key_handling.h"
#endif

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <openthread/error.h>
#include <openthread/platform/crypto.h>
#include <openthread/platform/radio.h>

/* AES-CCM constants (IEEE 802.15.4 / Thread) */
#define AES_CCM_NONCE_SIZE    IEEE802154_EXT_ADDR_LENGTH + sizeof(uint32_t) + sizeof(uint8_t)
#define AES_CCM_MIN_TAG_LEN   4
#define AES_CCM_MAX_TAG_LEN   16

/* IEEE 802.15.4 security level: encryption only = 4, enc+MIC-32 = 5, etc. */
#define SEC_LEVEL_ENC         4

#define FCS_SIZE               2

#define TX_SECURITY_BLOCK_SIZE 16
#define TX_SECURITY_KEY_BITS   128

/* Internal CCM context (used only by silabs_tx_ccm). */
typedef struct tx_security_ctx {
	uint8_t  block[TX_SECURITY_BLOCK_SIZE];
	uint8_t  ctr[TX_SECURITY_BLOCK_SIZE];
	uint8_t  ctr_pad[TX_SECURITY_BLOCK_SIZE];
	const uint8_t *key;
	uint32_t header_length;
	uint32_t header_cur;
	uint32_t plaintext_length;
	uint32_t plaintext_cur;
	uint16_t block_length;
	uint16_t ctr_length;
	uint8_t  nonce_length;
	uint8_t  tag_length;
} tx_security_ctx_t;

/* MIC sizes by security level (level 0–3 and 4–7) */
static const uint8_t mic_size_table[8] = { 0, 4, 8, 16, 0, 4, 8, 16 };

void silabs_generate_nonce(const uint8_t *ext_address,
			   uint32_t frame_counter,
			   uint8_t security_level,
			   uint8_t *nonce)
{
	memcpy(nonce, ext_address, IEEE802154_EXT_ADDR_LENGTH);
	nonce += IEEE802154_EXT_ADDR_LENGTH;
	sys_memcpy_swap(nonce, &frame_counter, sizeof(uint32_t));
	nonce += sizeof(uint32_t);
	nonce[0] = security_level;
}

#if defined(RADIOAES_PRESENT)

static void tx_security_set_key(tx_security_ctx_t *ctx, const uint8_t *key)
{
	ctx->key = key;
}

static void tx_security_init(tx_security_ctx_t *ctx,
			     uint32_t header_length,
			     uint32_t plaintext_length,
			     uint8_t tag_length,
			     const void *nonce,
			     uint8_t nonce_length)
{
	const uint8_t *nonce_bytes = (const uint8_t *)nonce;
	uint8_t block_length = 0;
	uint32_t len;
	uint8_t L;
	uint8_t i;

	assert(((tag_length & 1) == 0) &&
	       tag_length >= AES_CCM_MIN_TAG_LEN &&
	       tag_length <= AES_CCM_MAX_TAG_LEN);

	L = 0;
	for (len = plaintext_length; len; len >>= 8)
		L++;
	if (L <= 1)
		L = 2;
	if (nonce_length > 13)
		nonce_length = 13;
	if (L < (15 - (uint8_t)nonce_length))
		L = 15 - nonce_length;
	if (nonce_length > (15 - L))
		nonce_length = 15 - L;

	ctx->block[0] = (uint8_t)((header_length != 0 ? 1 : 0) << 6) |
			(uint8_t)(((tag_length - 2) >> 1) << 3) |
			(uint8_t)(L - 1);
	memcpy(&ctx->block[1], nonce_bytes, nonce_length);

	len = plaintext_length;
	for (i = sizeof(ctx->block) - 1; i > nonce_length; i--) {
		ctx->block[i] = (uint8_t)(len & 0xff);
		len >>= 8;
	}

	sli_aes_crypt_ecb_radio(true, ctx->key, TX_SECURITY_KEY_BITS,
				ctx->block, ctx->block);

	if (header_length > 0) {
		if (header_length < (65536U - 256U)) {
			ctx->block[block_length++] ^= (uint8_t)(header_length >> 8);
			ctx->block[block_length++] ^= (uint8_t)(header_length);
		} else {
			ctx->block[block_length++] ^= 0xff;
			ctx->block[block_length++] ^= 0xfe;
			ctx->block[block_length++] ^= (uint8_t)(header_length >> 24);
			ctx->block[block_length++] ^= (uint8_t)(header_length >> 16);
			ctx->block[block_length++] ^= (uint8_t)(header_length >> 8);
			ctx->block[block_length++] ^= (uint8_t)header_length;
		}
	}

	ctx->ctr[0] = L - 1;
	memcpy(&ctx->ctr[1], nonce_bytes, nonce_length);
	memset(&ctx->ctr[nonce_length + 1], 0, sizeof(ctx->ctr) - (size_t)(nonce_length + 1));

	ctx->nonce_length     = nonce_length;
	ctx->header_length     = header_length;
	ctx->header_cur        = 0;
	ctx->plaintext_length = plaintext_length;
	ctx->plaintext_cur     = 0;
	ctx->block_length     = block_length;
	ctx->ctr_length       = sizeof(ctx->ctr_pad);
	ctx->tag_length       = tag_length;
}

static void tx_security_header(tx_security_ctx_t *ctx,
			       const void *header,
			       uint32_t header_length)
{
	const uint8_t *header_bytes = (const uint8_t *)header;
	unsigned int i;

	assert(ctx->header_cur + header_length <= ctx->header_length);

	for (i = 0; i < header_length; i++) {
		if (ctx->block_length == sizeof(ctx->block)) {
			sli_aes_crypt_ecb_radio(true, ctx->key, TX_SECURITY_KEY_BITS,
						ctx->block, ctx->block);
			ctx->block_length = 0;
		}
		ctx->block[ctx->block_length++] ^= header_bytes[i];
	}
	ctx->header_cur += header_length;

	if (ctx->header_cur == ctx->header_length && ctx->block_length != 0) {
		sli_aes_crypt_ecb_radio(true, ctx->key, TX_SECURITY_KEY_BITS,
					ctx->block, ctx->block);
		ctx->block_length = 0;
	}
}

static void tx_security_payload(tx_security_ctx_t *ctx,
				void *plain,
				void *cipher,
				uint32_t length)
{
	uint8_t *plain_bytes  = (uint8_t *)plain;
	uint8_t *cipher_bytes = (uint8_t *)cipher;
	uint8_t byte;
	unsigned int i;
	int j;

	assert(ctx->plaintext_cur + length <= ctx->plaintext_length);

	for (i = 0; i < length; i++) {
		if (ctx->ctr_length == 16) {
			for (j = (int)sizeof(ctx->ctr) - 1; j > (int)ctx->nonce_length; j--) {
				if (++ctx->ctr[j])
					break;
			}
			sli_aes_crypt_ecb_radio(true, ctx->key, TX_SECURITY_KEY_BITS,
						ctx->ctr, ctx->ctr_pad);
			ctx->ctr_length = 0;
		}
		byte = plain_bytes[i];
		cipher_bytes[i] = byte ^ ctx->ctr_pad[ctx->ctr_length++];
		if (ctx->block_length == sizeof(ctx->block)) {
			sli_aes_crypt_ecb_radio(true, ctx->key, TX_SECURITY_KEY_BITS,
						ctx->block, ctx->block);
			ctx->block_length = 0;
		}
		ctx->block[ctx->block_length++] ^= byte;
	}
	ctx->plaintext_cur += length;

	if (ctx->plaintext_cur >= ctx->plaintext_length) {
		if (ctx->block_length != 0)
			sli_aes_crypt_ecb_radio(true, ctx->key, TX_SECURITY_KEY_BITS,
						ctx->block, ctx->block);
		if (ctx->nonce_length + 1 < TX_SECURITY_BLOCK_SIZE)
			memset(&ctx->ctr[ctx->nonce_length + 1], 0,
			       sizeof(ctx->ctr) - (size_t)(ctx->nonce_length + 1));
	}
}

static uint8_t tx_security_get_tag_length(const tx_security_ctx_t *ctx)
{
	return ctx->tag_length;
}

static void tx_security_finalize(tx_security_ctx_t *ctx, void *tag)
{
	uint8_t *tag_bytes = (uint8_t *)tag;
	int i;

	assert(ctx->plaintext_cur == ctx->plaintext_length);

	sli_aes_crypt_ecb_radio(true, ctx->key, TX_SECURITY_KEY_BITS,
				ctx->ctr, ctx->ctr_pad);
	for (i = 0; i < ctx->tag_length; i++)
		tag_bytes[i] = ctx->block[i] ^ ctx->ctr_pad[i];
}

#endif /* RADIOAES_PRESENT */

#if defined(LPWAES_PRESENT)
/** Build a plaintext key descriptor from raw key bytes. */
static void create_plaintext_key_desc_from_bytes(const uint8_t *key_bytes,
						 sli_crypto_descriptor_t *key_desc)
{
	key_desc->engine = SLI_CRYPTO_LPWAES;
	key_desc->yield  = false;
	key_desc->location                         = SLI_CRYPTO_KEY_LOCATION_PLAINTEXT;
	key_desc->key.plaintext_key.buffer.pointer = (uint8_t *)key_bytes;
	key_desc->key.plaintext_key.buffer.size    = OT_MAC_KEY_SIZE;
	key_desc->key.plaintext_key.key_size       = OT_MAC_KEY_SIZE;
}
#endif

#if defined(RADIOAES_PRESENT) || defined(LPWAES_PRESENT)
bool silabs_tx_ccm(uint8_t *mpdu, uint16_t mpdu_len, uint8_t header_length,
		   uint8_t security_level, const uint8_t *key, const uint8_t *nonce)
{
	uint8_t  tag_length = mic_size_table[security_level & 0x07U];
	uint16_t payload_length = mpdu_len - header_length - FCS_SIZE - tag_length;
	uint8_t *payload = mpdu + header_length;
	uint8_t *footer  = mpdu + mpdu_len - FCS_SIZE - tag_length;

#if defined(RADIOAES_PRESENT)
	tx_security_ctx_t sec;

	tx_security_set_key(&sec, key);
	tx_security_init(&sec, header_length, payload_length, tag_length,
			 nonce, AES_CCM_NONCE_SIZE);
	tx_security_header(&sec, mpdu, header_length);
	tx_security_payload(&sec, payload, payload, payload_length);
	tx_security_finalize(&sec, footer);
	return true;
#elif defined(LPWAES_PRESENT)
	sli_crypto_descriptor_t key_desc;
	sl_status_t ret;

	create_plaintext_key_desc_from_bytes(key, &key_desc);
	ret = sli_crypto_ccm(&key_desc,
			     true,
			     (security_level >= SEC_LEVEL_ENC) ? payload : NULL,
			     (security_level >= SEC_LEVEL_ENC) ? payload_length : 0,
			     payload,
			     nonce,
			     AES_CCM_NONCE_SIZE,
			     mpdu,
			     header_length,
			     footer,
			     tag_length);
	return (ret == SL_STATUS_OK);
#endif
}
#endif

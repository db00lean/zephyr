/*
 * Copyright (c) 2026 Silicon Laboratories Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Declarations for symbols provided by the Simplicity SDK OpenThread platform
 * abstraction blob (libsl_openthread_cm33_gcc.a), linked from the HAL when
 * CONFIG_IEEE802154_SILABS_EFR32 is enabled. When CONFIG_BUILD_ONLY_NO_BLOBS is
 * set, a no-op stub is supplied by blob_stubs.c instead.
 */

#ifndef SL_OPENTHREAD_PAL_H
#define SL_OPENTHREAD_PAL_H

#ifdef __cplusplus
extern "C" {
#endif

void sl_openthread_init(void);

#ifdef __cplusplus
}
#endif

#endif /* SL_OPENTHREAD_PAL_H */

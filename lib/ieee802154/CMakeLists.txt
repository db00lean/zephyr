# SPDX-License-Identifier: Apache-2.0

zephyr_library()
zephyr_library_sources(ieee802154_frame.c)

# Include directories for internal dependencies
zephyr_library_include_directories(
  ${ZEPHYR_BASE}/subsys/net/l2/ieee802154
  ${ZEPHYR_BASE}/subsys/net/ip
)

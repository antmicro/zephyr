# Copyright (c) 2023 Antmicro <www.antmicro.com>
#
# SPDX-License-Identifier: Apache-2.0

zephyr_sources(soc.c)
zephyr_include_directories(.)

set_property(GLOBAL APPEND PROPERTY extra_post_build_commands
  COMMAND ${PYTHON_EXECUTABLE} ${SOC_DIR}/${ARCH}/${SOC_FAMILY}/common/siwx917_isp_prepare.py
  --rom_addr ${CONFIG_FLASH_BASE_ADDRESS}
  --out_hex ${KERNEL_HEX_NAME}
  ${KERNEL_BIN_NAME}
  ${KERNEL_BIN_NAME}
)

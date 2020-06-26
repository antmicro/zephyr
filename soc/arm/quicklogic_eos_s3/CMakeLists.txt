# Copyright (c) 2020 Antmicro <www.antmicro.com>
# SPDX-License-Identifier: Apache-2.0

zephyr_include_directories(${ZEPHYR_BASE}/drivers)
zephyr_sources(
  soc.c
  irq_handlers.c
  )
zephyr_sources_ifdef(CONFIG_EOS_S3_PROGRAM_FPGA fpga_loader.c)


# Copyright (c) 2020 Antmicro <www.antmicro.com>
# SPDX-License-Identifier: Apache-2.0

zephyr_include_directories(${ZEPHYR_BASE}/drivers)
zephyr_sources(
  soc.c
  irq_handlers.c
  fpga_loader.c
  )

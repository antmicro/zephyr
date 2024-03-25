# Copyright (c) 2019 Lexmark International, Inc.
# Copyright (c) 2024 Antmicro <www.antmicro.com>
#
# SPDX-License-Identifier: Apache-2.0

zephyr_sources(
  ../zynqmp_common/soc.c
)
zephyr_sources_ifdef(
  CONFIG_ARM_MPU
  arm_mpu_regions.c
)

zephyr_include_directories(
  .
  ../zynqmp_common/
)

if(CONFIG_SOC_XILINX_ZYNQMP_RPU_R8)
  set(SOC_LINKER_SCRIPT ${ZEPHYR_BASE}/include/zephyr/arch/arm/cortex_a_r/scripts/linker.ld CACHE INTERNAL "")
endif()

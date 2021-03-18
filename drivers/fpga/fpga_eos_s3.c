/*
 * Copyright (c) 2021 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <device.h>
#include <drivers/fpga.h>
#include "fpga_eos_s3.h"
#include <errno.h>

#define DT_DRV_COMPAT fpga

void eos_s3_fpga_enable_clk(void)
{
	CRU->C16_CLK_GATE = C16_CLK_GATE_PATH_0_ON;
	CRU->C21_CLK_GATE = C21_CLK_GATE_PATH_0_ON;
	CRU->C09_CLK_GATE = C09_CLK_GATE_PATH_1_ON | C09_CLK_GATE_PATH_2_ON;
	CRU->C02_CLK_GATE = C02_CLK_GATE_PATH_1_ON;
}

void eos_s3_fpga_disable_clk(void)
{
	CRU->C16_CLK_GATE = C16_CLK_GATE_PATH_0_OFF;
	CRU->C21_CLK_GATE = C21_CLK_GATE_PATH_0_OFF;
	CRU->C09_CLK_GATE = C09_CLK_GATE_PATH_1_OFF | C09_CLK_GATE_PATH_2_OFF;
	CRU->C02_CLK_GATE = C02_CLK_GATE_PATH_1_OFF;
}

static uint32_t eos_s3_fpga_get_status(const struct device *dev)
{
	return PMU->FB_STATUS;
}

static const char *eos_s3_fpga_get_info(const struct device *dev)
{
	return FGPA_INFO;
}

static int eos_s3_fpga_on(const struct device *dev)
{
	if (eos_s3_fpga_get_status(dev) == FB_STATUS_ACTIVE) {
		return -EPERM;
	}

	PMU->FFE_FB_PF_SW_WU = PMU_FFE_FB_PF_SW_WU_FB_WU;
	while (PMU->FFE_FB_PF_SW_WU == PMU_FFE_FB_PF_SW_WU_FB_WU) {
	};

	eos_s3_fpga_enable_clk();

	PMU->GEN_PURPOSE_0 = FB_CFG_ENABLE;
	PIF->CFG_CTL = CFG_CTL_LOAD_ENABLE;

	return 0;
}

static int eos_s3_fpga_off(const struct device *dev)
{
	if (eos_s3_fpga_get_status(dev) == FB_STATUS_SHUT_DOWN) {
		return -EPERM;
	}

	PMU->FB_PWR_MODE_CFG = PMU_FB_PWR_MODE_CFG_FB_SD;
	PMU->FFE_FB_PF_SW_PD = PMU_FFE_FB_PF_SW_PD_FB_PD;

	eos_s3_fpga_disable_clk();

	return 0;
}

static int eos_s3_fpga_reset(const struct device *dev)
{
	if (eos_s3_fpga_get_status(dev) == FB_STATUS_ACTIVE)
		eos_s3_fpga_off(dev);

	eos_s3_fpga_on(dev);

	if (eos_s3_fpga_get_status(dev) == FB_STATUS_SHUT_DOWN) {
		return -EAGAIN;
	}

	return 0;
}

static int eos_s3_fpga_load(const struct device *dev, uint32_t *image_ptr,
			    uint32_t img_size)
{
	if (eos_s3_fpga_get_status(dev) == FB_STATUS_SHUT_DOWN ||
	    eos_s3_fpga_get_status(dev) == FB_STATUS_DEEP_SLEEP) {
		return -EPERM;
	}

	volatile uint32_t *bitstream = (volatile uint32_t *)image_ptr;

	for (uint32_t chunk_cnt = 0; chunk_cnt < (img_size / 4); chunk_cnt++) {
		PIF->CFG_DATA = *bitstream;
		bitstream++;
	}

	PMU->GEN_PURPOSE_0 = FB_CFG_DISABLE;
	PIF->CFG_CTL = CFG_CTL_LOAD_DISABLE;
	PMU->FB_ISOLATION = FB_ISOLATION_DISABLE;

	return 0;
}

static int eos_s3_fpga_init(const struct device *dev)
{
	IO_MUX->PAD_19_CTRL = PAD_ENABLE;

	eos_s3_fpga_reset(dev);

	return 0;
}

static const struct fpga_driver_api eos_s3_api = {
	.reset = eos_s3_fpga_reset,
	.load = eos_s3_fpga_load,
	.get_status = eos_s3_fpga_get_status,
	.on = eos_s3_fpga_on,
	.off = eos_s3_fpga_off,
	.get_info = eos_s3_fpga_get_info
};

DEVICE_DEFINE(fpga, "FPGA", eos_s3_fpga_init, device_pm_control_nop, NULL, NULL,
	      APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEVICE, &eos_s3_api);
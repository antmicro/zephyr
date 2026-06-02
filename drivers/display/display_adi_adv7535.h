/*
 * Copyright (c) 2026 Antmicro <www.antmicro.com>
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef INCLUDE_DISPLAY_DISPLAY_ADI_ADV7535_H_
#define INCLUDE_DISPLAY_DISPLAY_ADI_ADV7535_H_

#include <zephyr/kernel.h>

#define ADV7535_REG_POWER 0x41
#define ADV7535_POWER_UP 0
#define ADV7535_POWER_DOWN 1

struct reg_val_pair {
	uint8_t reg, val;
};

const struct reg_val_pair adv7535_fixed_registers[] = {
	{ 0x16, 0x20 },
	{ 0x9a, 0xe0 },
	{ 0xba, 0x70 },
	{ 0xde, 0x82 },
	{ 0xe4, 0x40 },
	{ 0xe5, 0x80 },
};

const struct reg_val_pair adv7535_cec_fixed_registers[] = {
	{ 0x15, 0xd0 },
	{ 0x17, 0xd0 },
	{ 0x24, 0x20 },
	{ 0x57, 0x11 },
	{ 0x05, 0xc8 },
};

#endif  /* INCLUDE_DISPLAY_DISPLAY_ADI_ADV7535_H_ */

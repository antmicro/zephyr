/*
 * Copyright (c) 2026 Antmicro <www.antmicro.com>
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef INCLUDE_DISPLAY_DISPLAY_ADI_ADV7535_H_
#define INCLUDE_DISPLAY_DISPLAY_ADI_ADV7535_H_

#include <zephyr/kernel.h>

#define ADV7535_I2C_PACKET_ADDR_DEFAULT 0x38
#define ADV7535_I2C_EDID_ADDR_DEFAULT 0x3f
#define ADV7535_I2C_CEC_ADDR_DEFAULT 0x3c

#define ADV7535_REG_REVISION 0x00

#define ADV7535_REG_POWER 0x41
#define ADV7535_POWER_UP 0
#define ADV7535_POWER_DOWN 1

#define ADV7535_REG_ENABLE_0 0x40

#define ADV7535_ENABLE_0_PACKET_SPARE_1    BIT(0)
#define ADV7535_ENABLE_0_PACKET_SPARE_2    BIT(1)
#define ADV7535_ENABLE_0_PACKET_GM         BIT(2)
#define ADV7535_ENABLE_0_PACKET_ISRC       BIT(3)
#define ADV7535_ENABLE_0_PACKET_ACP        BIT(4)
#define ADV7535_ENABLE_0_PACKET_MPEG       BIT(5)
#define ADV7535_ENABLE_0_PACKET_SPD        BIT(6)
#define ADV7535_ENABLE_0_PACKET_GC         BIT(7)

#define ADV7535_REG_ENABLE_1 0x44

#define ADV7535_ENABLE_1_PACKET_MEM_READ_MODE    BIT(0)
/* Bits 1 and 2 are reserved and should not be used */
#define ADV7535_ENABLE_1_AUDIO_INFO_FRAME        BIT(3)
#define ADV7535_ENABLE_1_AVI_INFO_FRAME          BIT(4)
#define ADV7535_ENABLE_1_PACKET_AUDIO_SAMPLE     BIT(5)
#define ADV7535_ENABLE_1_PACKET_N_CTS            BIT(6)
/* Bit 7 is reserved and should not be used */

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

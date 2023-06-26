/*
 * Copyright (c) 2023 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT silabs_siwx917_pinctrl

#include <zephyr/drivers/pinctrl.h>
#include <soc.h>
#include "rsi_rom_egpio.h"

static int pinctrl_siwx917_set(uint8_t port, uint8_t pin, uint8_t mux)
{
	RSI_EGPIO_HostPadsGpioModeEnable(pin);
	RSI_EGPIO_PadReceiverEnable(pin);
	RSI_EGPIO_SetPinMux(EGPIO, port, pin, mux);

	return 0;
}

int pinctrl_configure_pins(const pinctrl_soc_pin_t *pins, uint8_t pin_cnt, uintptr_t reg)
{
	ARG_UNUSED(reg);
	int i;

	for (i = 0; i < pin_cnt; i++) {
		pinctrl_siwx917_set(pins[i].port, pins[i].pin, pins[i].mux);
	}

	return 0;
}

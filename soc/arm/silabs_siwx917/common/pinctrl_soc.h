/*
 * Copyright (c) 2023 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_SOC_ARM_SILABS_SIWX917_PINCTRL_H_
#define ZEPHYR_SOC_ARM_SILABS_SIWX917_PINCTRL_H_

#include <zephyr/types.h>

typedef struct pinctrl_soc_pin_t {
	uint8_t port;
	uint8_t pin;
	uint8_t mux;
} pinctrl_soc_pin_t;

#define SILABS_SIWX917_DT_PIN(node_id)				\
	{							\
		.port = DT_PROP_BY_IDX(node_id, pinmux, 0),	\
		.pin  = DT_PROP_BY_IDX(node_id, pinmux, 1),	\
		.mux  = DT_PROP_BY_IDX(node_id, pinmux, 2),	\
	},

#define Z_PINCTRL_STATE_PIN_INIT(node_id, prop, idx)		\
	SILABS_SIWX917_DT_PIN(DT_PROP_BY_IDX(node_id, prop, idx))

#define Z_PINCTRL_STATE_PINS_INIT(node_id, prop)		\
	{ DT_FOREACH_PROP_ELEM(node_id, prop, Z_PINCTRL_STATE_PIN_INIT) }

#endif /* ZEPHYR_SOC_ARM_SILABS_SIWX917_PINCTRL_H_ */

/*
 * Copyright (c) 2024 Open Pixel Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/device.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(main, LOG_LEVEL_DBG);

// #define ADV7535_NODE  DT_NODELABEL(adv7535)

#define ADV7535_RST_NODE DT_NODELABEL(adv7535_rst)

// static const struct i2c_dt_spec adv7535 = I2C_DT_SPEC_GET(ADV7535_NODE);
static const struct gpio_dt_spec adv_reset = GPIO_DT_SPEC_GET(ADV7535_RST_NODE, gpios);

int main()
{
	// Check if I2C bus got initialized
	// if (!device_is_ready(adv7535.bus)) {
	// 	LOG_ERR("ADV7535 bus not ready");
	// }
	LOG_INF("Main");

	// Set ADC7535 reset to high
	gpio_pin_configure_dt(&adv_reset, GPIO_OUTPUT_INACTIVE);

	// Check ADC7535 ID registers read
	// int status = 0;
	// uint16_t adc7535_id = 0;

	// Read ID from regs 0 and 1
	// status = i2c_burst_read_dt(&adv7535, 0, (uint8_t *)&adc7535_id, sizeof(adc7535_id));

	// if (status) {
	// 	LOG_ERR("ADV7535 read failed");
	// } else {
	// 	LOG_INF("ADV7535 read ID: %u", adc7535_id);
	// }
	//
	// i2c_reg_write_byte(adv7535.bus, 0x38, 0x41, 0x00);
	// i2c_reg_write_byte(adv7535.bus, 0x3c, 0x27, 0xcb);
	// i2c_reg_write_byte(adv7535.bus, 0x3c, 0x27, 0x8b);
	// i2c_reg_write_byte(adv7535.bus, 0x3c, 0x27, 0xcb);
	// i2c_reg_write_byte(adv7535.bus, 0x3c, 0x03, 0x89);
	// i2c_reg_write_byte(adv7535.bus, 0x3c, 0x55, 0x80);

	return 0;
}

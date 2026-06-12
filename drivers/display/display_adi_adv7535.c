/*
 * Copyright (c) 2026 Antmicro <www.antmicro.com>
 * SPDX-License-Identifier: Apache-2.0
 *
 * Driver implementation based on ST sample from:
 * https://github.com/STMicroelectronics/stm32-adv7533
 */

#define DT_DRV_COMPAT adi_adv7535

#include "zephyr/drivers/gpio.h"
#include <zephyr/device.h>
#include <zephyr/init.h>
#include <zephyr/drivers/display.h>
#include <zephyr/drivers/mipi_dsi.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "display_adi_adv7535.h"

LOG_MODULE_REGISTER(adi_adv7535, CONFIG_DISPLAY_LOG_LEVEL);

struct adv7535_i2c_conf {
	uint8_t edid_addr;
	uint8_t packet_addr;
	uint8_t cec_addr;
	uint8_t fixed_addr;
	struct i2c_dt_spec i2c;
};

struct adv7535_config {
	const struct device *mipi_dsi_host;
	uint8_t channel;
	uint8_t num_of_lanes;
	struct adv7535_i2c_conf i2c_conf;
	struct gpio_dt_spec dt_pd;
};

struct adv7535_data {
	uint8_t enable_1_reg;
	uint8_t enable_2_reg;
	uint8_t pixel_format;
};

static bool adv7535_i2c_bus_ready(const struct device *dev)
{
	const struct adv7535_config *config = dev->config;

	return i2c_is_ready_dt(&config->i2c_conf.i2c);
}

static const char *adv7535_i2c_bus_name(const struct device *dev)
{
	const struct adv7535_config *config = dev->config;

	return config->i2c_conf.i2c.bus->name;
}

static int adv7535_generic_write(const struct device *dev, uint8_t i2c_addr, uint8_t reg, uint8_t val)
{
	const struct adv7535_config *config = dev->config;
	const struct device *i2c_dev = config->i2c_conf.i2c.bus;
	int ret = 0;
	uint8_t buf[2];

	buf[0] = reg;
	buf[1] = val;

	ret = i2c_write(i2c_dev, buf, 2, i2c_addr);
	if (ret) {
		LOG_ERR("Could not write to address 0x%02x, register 0x%02x, value 0x%02x",
			i2c_addr, reg, val);
	}

	return ret;
}

static int adv7535_generic_read(const struct device *dev, uint8_t i2c_addr, uint8_t reg, uint8_t *buf)
{
	const struct adv7535_config *config = dev->config;
	const struct device *i2c_dev = config->i2c_conf.i2c.bus;
	int ret = 0;

	ret = i2c_write_read(i2c_dev, i2c_addr, &reg, 1, buf, 1);
	if (ret) {
		LOG_ERR("Could not read address 0x%02x, register 0x%02x", i2c_addr, reg);
	}

	return ret;
}

static int adv7535_write(const struct device *dev, uint8_t reg, uint8_t val)
{
	const struct adv7535_config *config = dev->config;
	return adv7535_generic_write(dev, config->i2c_conf.i2c.addr, reg, val);
}

static int adv7535_read(const struct device *dev, uint8_t reg, uint8_t *buf)
{
	const struct adv7535_config *config = dev->config;
	return adv7535_generic_read(dev, config->i2c_conf.i2c.addr, reg, buf);
}

static int adv7535_write_cec(const struct device *dev, uint8_t reg, uint8_t val)
{
	const struct adv7535_config *config = dev->config;
	return adv7535_generic_write(dev, config->i2c_conf.cec_addr, reg, val);
}

static int adv7535_read_cec(const struct device *dev, uint8_t reg, uint8_t *buf)
{
	const struct adv7535_config *config = dev->config;
	return adv7535_generic_read(dev, config->i2c_conf.cec_addr, reg, buf);
}

static int adv7535_set_fixed_registers(const struct device* dev)
{
	int ret = 0;
	uint8_t val;

	ARRAY_FOR_EACH(adv7535_fixed_registers, i){
		ret = adv7535_write(dev, adv7535_fixed_registers[i].reg,
		      adv7535_fixed_registers[i].val);
		if(ret){
			return ret;
		}

		ret = adv7535_read(dev, adv7535_fixed_registers[i].reg, &val);
		if(ret){
			return ret;
		}

		if (adv7535_fixed_registers[i].val != val) {
			LOG_WRN("main: reg: 0x%02x; expected: 0x%02x; read: 0x%02x",
				adv7535_fixed_registers[i].reg,
				adv7535_fixed_registers[i].val, val);
		}
	}

	return ret;
}

static int adv7535_set_cec_fixed_registers(const struct device* dev)
{
	int ret = 0;
	uint8_t val;

	ARRAY_FOR_EACH(adv7535_cec_fixed_registers, i){
		ret = adv7535_write_cec(dev, adv7535_cec_fixed_registers[i].reg,
		      adv7535_cec_fixed_registers[i].val);
		if(ret){
			return ret;
		}

		ret = adv7535_read_cec(dev, adv7535_cec_fixed_registers[i].reg, &val);
		if(ret){
			return ret;
		}

		if (adv7535_cec_fixed_registers[i].val != val) {
			LOG_WRN("cec: reg: 0x%02x; expected: 0x%02x; read: 0x%02x",
				adv7535_cec_fixed_registers[i].reg,
				adv7535_cec_fixed_registers[i].val, val);
		}
	}

	return ret;
}

static int adv7535_power_up(const struct device *dev)
{
	int ret = 0;
	uint8_t pd_reg;

	ret = adv7535_read(dev, ADV7535_REG_POWER, &pd_reg);
	if (ret) {
		return ret;
	}

	if (pd_reg & ADV7535_POWER_DOWN){
		ret = adv7535_write(dev, ADV7535_REG_POWER, pd_reg & ~ADV7535_POWER_DOWN);
		if (ret) {
			return ret;
		}
	} else {
		LOG_INF("Tried to power up ADV7535, while it is already powered up");
		return 0;
	}

	return ret;
}

static int adv7535_power_down(const struct device *dev)
{
	int ret = 0;
	uint8_t pd_reg;

	ret = adv7535_read(dev, ADV7535_REG_POWER, &pd_reg);
	if (ret) {
		return ret;
	}

	if (pd_reg & ADV7535_POWER_DOWN){
		LOG_INF("Tried to power down ADV7535, while it is already powered down");
		return 0;
	} else {
		ret = adv7535_write(dev, ADV7535_REG_POWER, pd_reg | ADV7535_POWER_DOWN);
		if (ret) {
			return ret;
		}
	}

	return ret;
}

static int adv7535_attach_to_mipi_dsi_host(const struct device* dev)
{
	const struct adv7535_config *config = dev->config;
	struct adv7535_data *data = dev->data;
	int ret;
	struct mipi_dsi_device mdev = {0};

	mdev.data_lanes = config->num_of_lanes;
	mdev.pixfmt = data->pixel_format;

	mdev.mode_flags =
		MIPI_DSI_MODE_VIDEO_HSE | MIPI_DSI_MODE_VIDEO | MIPI_DSI_CLOCK_NON_CONTINUOUS;

	ret = mipi_dsi_attach(config->mipi_dsi_host, config->channel, &mdev);
	if (ret < 0) {
		LOG_ERR("Could not attach to MIPI-DSI host");
		return ret;
	}

	return 0;
}

static int adv7535_set_i2c_addresses(const struct device *dev)
{
	const struct adv7535_config *config = dev->config;
	struct reg_val_pair addresses[] = {
		{ ADV7535_REG_EDID_ADDR, config->i2c_conf.edid_addr},
		{ ADV7535_REG_PACKET_MEM_ADDR, config->i2c_conf.packet_addr},
		{ ADV7535_REG_CEC_ADDR, config->i2c_conf.cec_addr},
		{ ADV7535_REG_FIXED_ADDR, config->i2c_conf.fixed_addr},
	};
	int ret = 0;

	/* NOTE: Main address is set by the state on the Power Down pin during power up */

	ARRAY_FOR_EACH(addresses, i) {
		ret = adv7535_write(dev, addresses[i].reg, addresses[i].val << 1);
		if (ret) {
			return ret;
		}
	}

	return ret;
}

static int adv7535_dsi_power_on(const struct device *dev)
{
	const struct adv7535_config *config = dev->config;
	int ret = 0;
	uint8_t tmp;

	/* This function is a part of ADV7533_Configure in STM driver
	 * And is pretty much 1 to 1 with adv7533_dsi_power_on from the Linux driver
	 */

	ret = adv7535_write_cec(dev, 0x1C, config->num_of_lanes << 4);
	if (ret){
		return ret;
	}

	/* Idk if this should be behind an if statement with boolean internal_timing_gen set in
	 * device tree, also add early return on error
	 */
	if (true) {
		/* Reset internal timing generator */
		adv7535_write_cec(dev, 0x27, 0xcb);
		adv7535_write_cec(dev, 0x27, 0x8b);
		adv7535_write_cec(dev, 0x27, 0xcb);
	} else {
		/* Disable interlan timing generator */
		adv7535_write_cec(dev, 0x27, 0x0b);
	}

	/* Enable HDMI */
	adv7535_write_cec(dev, 0x03, 0x89);

	/* Disable test mode */
	// adv7535_write_cec(dev, 0x55, 0x00);

	adv7535_set_cec_fixed_registers(dev);

	/* Code below is only in the STM driver */

	/* Enable GC packet */
	adv7535_read(dev, ADV7535_REG_ENABLE_0, &tmp);
	tmp |= ADV7535_ENABLE_0_PACKET_GC;
	adv7535_write(dev, ADV7535_REG_ENABLE_0, tmp);

	/* Input color depth 24-bit per pixel */
	adv7535_read(dev, 0x4C, &tmp);
	tmp &= ~0x0FU;
	tmp |= 0x03U;
	adv7535_write(dev, 0x4C, tmp);

	/* Down dither output color depth */
	adv7535_write(dev, 0x49, 0xFC);

	return ret;
}

static int adv7535_enable_test_pattern(const struct device *dev)
{
	// adv7535_write_cec(dev, 0x16, 0x00);

	// Color bars
	adv7535_write_cec(dev, 0x55, 0x80);

	// Grayscale gradient
	// adv7535_write_cec(dev, 0x55, 0xA0);

	// A magic value from from the ST sample (linked at the top of the file)
	adv7535_write_cec(dev, 0xAF, 0x16);

	return 0;
}

static int adv7535_configure_gpio(const struct device *dev)
{
	const struct adv7535_config *config = dev->config;
	int ret = 0;

	if (config->dt_pd.port) {
		if (!gpio_is_ready_dt(&config->dt_pd)) {
			LOG_ERR("GPIO device %s not ready",
				config->dt_pd.port->name);
			return -EIO;
		}

		ret = gpio_pin_configure_dt(&config->dt_pd,
					    GPIO_OUTPUT_INACTIVE);
		if (ret) {
			LOG_ERR("Failed to configure GPIO pin %u",
				config->dt_pd.pin);
			return ret;
		}
	}

	return ret;
}

static int adv7535_reset(const struct device *dev)
{
	const struct adv7535_config *config = dev->config;
	int ret = 0;

	if (config->dt_pd.port) {
		ret = gpio_pin_set_dt(&config->dt_pd, 1);
		k_msleep(5);
		ret |= gpio_pin_set_dt(&config->dt_pd, 0);
		LOG_DBG("Reset using Power Down pin");
	} else {
		ret = adv7535_power_down(dev);
		ret |= adv7535_power_up(dev);
		LOG_DBG("Reset using Power Down register");
	}

	if (ret){
		LOG_ERR("Failed to preform a reset");
	}

	return ret;
}

static int adv7535_init(const struct device *dev)
{
	const struct adv7535_config *config = dev->config;
	struct adv7535_data *data = dev->data;
	int ret;
	uint8_t revision;

	LOG_ERR("Log from driver init function");

	if (!adv7535_i2c_bus_ready(dev)) {
		LOG_ERR("Bus device %s not ready!", adv7535_i2c_bus_name(dev));
		return -EINVAL;
	}

	ret = adv7535_configure_gpio(dev);
	if (ret) {
		LOG_ERR("Failed configuring GPIO");
		return ret;
	}

	ret = adv7535_reset(dev);
	if (ret) {
		LOG_ERR("Failed reseting the device");
		return ret;

	}

	ret = adv7535_set_i2c_addresses(dev);
	if (ret) {
		LOG_ERR("Failed setting the I2C addresses");
		return ret;
	}

	// Override HPD to be high so adv7535 can turn on
	uint8_t hpd_control_register;
	adv7535_read(dev, 0xd6, &hpd_control_register);
	hpd_control_register |= 0x40U;
	adv7535_write(dev, 0xd6, hpd_control_register);

	/* Is adv7535_power_down call needed here? */
	// adv7535_power_down(dev);
	adv7535_power_up(dev);

	ret = adv7535_set_fixed_registers(dev);
	if (ret){
		LOG_ERR("Failed to set fixed registers: %d", ret);
	}

	/* Disable all packets */
	adv7535_write(dev, ADV7535_REG_ENABLE_0, 0);
	adv7535_write(dev, ADV7535_REG_ENABLE_1, 0);

	ret = adv7535_set_cec_fixed_registers(dev);
	if (ret){
		LOG_ERR("Failed to set CEC fixed registers: %d", ret);
	}

	/* Enable CEC */
	adv7535_write(dev, ADV7535_REG_CEC_POWER_DOWN, ADV7535_CEC_POWER_DOWN);

	adv7535_dsi_power_on(dev);
	adv7535_enable_test_pattern(dev);

	ret = adv7535_attach_to_mipi_dsi_host(dev);
	if (ret) {
		LOG_ERR("Failed to attach to MIPI DSI host: %d", ret);
		return ret;
	}

	// TODO: Add general info here like i2c addresses, channel etc.
	adv7535_read(dev, 0x00, &revision);
	LOG_DBG("ADV7535 initialized. Chip Revision: %d", revision);

	// adv7535_reset(dev);

	return 0;
}

#define ADV7535_IS_PD_ACTIVE_LOW(id) (DT_INST_GPIO_FLAGS(id, pd_gpios) & GPIO_ACTIVE_LOW)

#define ADV7535_IS_PD_AND_ADDR_VALID(id) \
	((DT_INST_REG_ADDR(id) == 0x39 && !(ADV7535_IS_PD_ACTIVE_LOW(id))) || \
	(DT_INST_REG_ADDR(id) == 0x3d && (ADV7535_IS_PD_ACTIVE_LOW(id))))

#define ADV7535_VALIDATE_PD_AND_ADDR(id) \
	IF_ENABLED(DT_INST_NODE_HAS_PROP(id, pd_gpios), \
	(BUILD_ASSERT((ADV7535_IS_PD_AND_ADDR_VALID(id)), \
		"ADV7535 I2C address does not match pd-gpios polarity. " \
		"0x39 requres active high, 0x3d requres active low." \
	      )) \
	);

#define ADV7535_DEFINE(id)                                                               \
	static const struct adv7535_config config_##id = {                               \
		.mipi_dsi_host = DEVICE_DT_GET(DT_INST_PHANDLE(id, mipi_dsi)),                          \
		.channel = DT_INST_PROP(id, dsi_channel), \
		.num_of_lanes = DT_INST_PROP_BY_IDX(id, data_lanes, 0),                            \
		.i2c_conf = { \
			.i2c = I2C_DT_SPEC_INST_GET(id),                                          \
			.edid_addr = DT_INST_PROP_OR(id, edid_addr, ADV7535_I2C_EDID_ADDR_DEFAULT), \
			.packet_addr = DT_INST_PROP_OR(id, packet_addr, ADV7535_I2C_PACKET_ADDR_DEFAULT), \
			.cec_addr = DT_INST_PROP_OR(id, cec_addr, ADV7535_I2C_CEC_ADDR_DEFAULT), \
			.fixed_addr = DT_INST_PROP_OR(id, fixed_addr, ADV7535_I2C_FIXED_ADDR_DEFAULT), \
		}, \
		.dt_pd = GPIO_DT_SPEC_INST_GET_OR(id, pd_gpios, {0}) \
	};                                                                                         \
	static struct adv7535_data data_##id = {                                         \
		.pixel_format = DT_INST_PROP(id, pixel_format),                                    \
	};                                                                                         \
	DEVICE_DT_INST_DEFINE(id, adv7535_init, NULL, &data_##id, &config_##id,          \
			      POST_KERNEL, CONFIG_DISPLAY_INIT_PRIORITY, NULL); \
	ADV7535_VALIDATE_PD_AND_ADDR(id)

DT_INST_FOREACH_STATUS_OKAY(ADV7535_DEFINE)

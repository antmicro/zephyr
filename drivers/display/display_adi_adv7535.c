/*
 * Copyright (c) 2026 Antmicro <www.antmicro.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT adi_adv7535

#include <string.h>
#include <zephyr/device.h>
#include <zephyr/init.h>
#include <zephyr/drivers/display.h>
#include <zephyr/drivers/mipi_dsi.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "display_adi_adv7535.h"

LOG_MODULE_REGISTER(adi_adv7535, CONFIG_DISPLAY_LOG_LEVEL);

struct adv7535_config {
	const struct device *mipi_dsi_host;
	uint8_t channel;
	uint8_t num_of_lanes;
	struct i2c_dt_spec i2c;
};

struct adv7535_data {
	uint8_t pixel_format;
};

static bool adv7535_i2c_bus_ready(const struct device *dev)
{
	const struct adv7535_config *config = dev->config;

	return i2c_is_ready_dt(&config->i2c);
}

static const char *adv7535_i2c_bus_name(const struct device *dev)
{
	const struct adv7535_config *config = dev->config;

	return config->i2c.bus->name;
}

static int adv7535_write(const struct device *dev, uint8_t reg, uint8_t val)
{
	const struct adv7535_config *config = dev->config;
	uint8_t buf[2];

	buf[0] = reg;
	buf[1] = val;

	return i2c_write_dt(&config->i2c, buf, 2);
}

static int adv7535_power_up(const struct device *dev)
{
	return adv7535_write(dev, ADV7535_REG_POWER, ADV7535_REG_POWER_UP);
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

static int adv7535_init(const struct device *dev)
{
	const struct adv7535_config *config = dev->config;
	struct adv7535_data *data = dev->data;
	int ret;

	if (!adv7535_i2c_bus_ready(dev)) {
		LOG_ERR("Bus device %s not ready!", adv7535_i2c_bus_name(dev));
		return -EINVAL;
	}

	// TODO: Remeber to handle the reset gpio
	// TODO: Init the whole thing here

	ret = adv7535_attach_to_mipi_dsi_host(dev);
	if (ret) {
		LOG_ERR("Failed to attach to MIPI DSI host: %d", ret);
		return ret;
	}

	LOG_DBG("ADV7535 initialized");

	return 0;
}

#define ADV7535_DEFINE(id)                                                               \
	static const struct adv7535_config config_##id = {                               \
		.mipi_dsi_host = DEVICE_DT_GET(DT_INST_PHANDLE(id, mipi_dsi)),                          \
		.channel = DT_INST_REG_ADDR(id),                                                   \
		.num_of_lanes = DT_INST_PROP_BY_IDX(id, data_lanes, 0),                            \
		.i2c = I2C_DT_SPEC_INST_GET(id),                                          \
	};                                                                                         \
	static struct adv7535_data data_##idadv7535= {                                         \
		.pixel_format = DT_INST_PROP(id, pixel_format),                                    \
	};                                                                                         \
	DEVICE_DT_INST_DEFINE(id, adv7535_init, NULL, &data_##id, &config_##id,          \
			      POST_KERNEL, CONFIG_DISPLAY_INIT_PRIORITY, NULL);

DT_INST_FOREACH_STATUS_OKAY(ADV7535_DEFINE)

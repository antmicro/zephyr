/*
 * Copyright (c) 2024 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT silabs_siwx917_i2c

#include <errno.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/pinctrl.h>

struct i2c_siwx917_config {
	const struct pinctrl_dev_config *pcfg;
};

struct i2c_siwx917_data {
};

static int i2c_siwx917_read(const struct device *dev, struct i2c_msg *msg, uint16_t addr)
{
	printk("%s\n", __func__);

	return 0;
}

static int i2c_siwx917_write(const struct device *dev, struct i2c_msg *msg, uint16_t addr)
{
	printk("%s\n", __func__);

	return 0;
}

static int i2c_siwx917_configure(const struct device *dev, uint32_t dev_config)
{
	printk("%s\n", __func__);

	return 0;
}

static int i2c_siwx917_transfer(const struct device *dev, struct i2c_msg *msgs, uint8_t num_msgs,
			      uint16_t addr)
{
	printk("%s\n", __func__);

	return 0;
}

static int i2c_siwx917_init(const struct device *dev)
{
	printk("%s\n", __func__);

	const struct i2c_siwx917_config *config = dev->config;
	int ret = 0;

	ret = pinctrl_apply_state(config->pcfg, PINCTRL_STATE_DEFAULT);

	return ret;
}

static struct i2c_driver_api i2c_siwx917_driver_api = {
	.configure = i2c_siwx917_configure,
	.transfer = i2c_siwx917_transfer,
};

#define SIWX917_I2C_DEFINE(n)										\
	PINCTRL_DT_INST_DEFINE(n);									\
	static struct i2c_siwx917_data i2c_siwx917_data##n;						\
	static const struct i2c_siwx917_config i2c_siwx917_config##n = {				\
		.pcfg = PINCTRL_DT_INST_DEV_CONFIG_GET(n),						\
	};												\
	I2C_DEVICE_DT_INST_DEFINE(n, i2c_siwx917_init, NULL, &i2c_siwx917_data##n,			\
				  &i2c_siwx917_config##n, POST_KERNEL, CONFIG_I2C_INIT_PRIORITY,	\
				  &i2c_siwx917_driver_api);

DT_INST_FOREACH_STATUS_OKAY(SIWX917_I2C_DEFINE)

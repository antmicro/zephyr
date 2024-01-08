/*
 * Copyright (c) 2024 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT silabs_siwx917_spi

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(spi_silabs_siwx917);

#include "spi_context.h"
#include <zephyr/drivers/spi.h>
#include <zephyr/drivers/pinctrl.h>
#include <zephyr/kernel.h>
#include <errno.h>

struct spi_siwx917_config {
	uint32_t base;
	uint32_t size;
};

struct spi_siwx917_data {
	struct spi_context ctx;
};


static int spi_config(const struct device *dev, const struct spi_config *config)
{

	int ret = 0;
	return ret;
}

static int spi_siwx917_xfer(const struct device *dev, const struct spi_config *config)
{
 int ret = 0;
	return ret;
}

static int spi_siwx917_transceive(const struct device *dev, const struct spi_config *config,
				const struct spi_buf_set *tx_bufs,
				const struct spi_buf_set *rx_bufs)
{
	int ret = 0;
	return ret;
}

static int spi_siwx917_release(const struct device *dev, const struct spi_config *config)
{
	return 0;
}

static struct spi_driver_api spi_siwx917_driver_api = {
	.transceive = spi_siwx917_transceive,
	.release = spi_siwx917_release,
};

static int spi_siwx917_init(const struct device *dev)
{
	int ret = 0;
	return ret;
}

#define SIWX917_SPI_INIT(n)                                                          \
	PINCTRL_DT_INST_DEFINE(n);                                                          \
	static struct spi_siwx917_data spi_siwx917_data##n = {                              \
		SPI_CONTEXT_INIT_LOCK(spi_siwx917_data##n, ctx),                                   \
		SPI_CONTEXT_INIT_SYNC(spi_siwx917_data##n, ctx)};                                  \
	static const struct spi_siwx917_config spi_siwx917_config##n = {                    \
		.base = DT_INST_REG_ADDR(n),                                                       \
		.size = DT_INST_REG_SIZE(n),                                                       \
	};																																																																																		\
	DEVICE_DT_INST_DEFINE(n, spi_siwx917_init, NULL, &spi_siwx917_data##n, &spi_siwx917_config##n,   \
			      POST_KERNEL, CONFIG_SPI_INIT_PRIORITY, &spi_siwx917_driver_api);

DT_INST_FOREACH_STATUS_OKAY(SIWX917_SPI_INIT)

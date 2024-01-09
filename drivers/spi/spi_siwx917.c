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
#include <stdlib.h>

#include "sl_si91x_gspi.h"

#define INTF_PLL_CLK            180000000
#define INTF_PLL_REF_CLK        40000000
#define SOC_PLL_CLK             20000000
#define SOC_PLL_REF_CLK         40000000
#define INTF_PLL_500_CTRL_VALUE 0xD900
#define SOC_PLL_MM_COUNT_LIMIT  0xA4
#define DVISION_FACTOR          0
#define SWAP_READ_DATA          1
#define SWAP_WRITE_DATA         0
#define GSPI_BITRATE            10000000
#define GSPI_BIT_WIDTH          8

struct spi_siwx917_config {
	uint32_t base;
	uint32_t size;
};

struct spi_siwx917_data {
	struct spi_context ctx;
	sl_gspi_handle_t gspi_driver_handle;
};

static int spi_siwx917_transfer_next_packet(const struct device *dev)
{
	struct spi_siwx917_data *data = dev->data;
	struct spi_context *ctx = &data->ctx;
	int transfer_len = ctx->tx_len;
	int ret = 0;

	/*
	 * According to the zephyr documentation of spi_buf, the TX buffer can be NULL, in which
	 * case NOP frames should be sent.
	 */
	const void *tx_buf = ctx->tx_buf ? ctx->tx_buf : calloc(ctx->tx_len, 1);
	void *rx_buf = ctx->rx_buf ? ctx->rx_buf : calloc(ctx->rx_len, 1);

	memset(rx_buf, 0, ctx->rx_len);
	if (ctx->tx_len > ctx->rx_len && ctx->rx_len > 0) {
		transfer_len = ctx->rx_len;
	}

	if (ctx->rx_buf == NULL) {
		ret = sl_si91x_gspi_send_data(data->gspi_driver_handle, tx_buf, transfer_len);
	} else {
		ret = sl_si91x_gspi_transfer_data(data->gspi_driver_handle, tx_buf, rx_buf,
				transfer_len);
	}

	if (ctx->tx_buf == NULL) {
		free(tx_buf);
	}
	if (ctx->rx_buf == NULL) {
		free(rx_buf);
	}

	spi_context_update_tx(ctx, 1, transfer_len);
	spi_context_update_rx(ctx, 1, transfer_len);

	return ret;
}

static int spi_siwx917_transceive(const struct device *dev, const struct spi_config *config,
				const struct spi_buf_set *tx_bufs,
				const struct spi_buf_set *rx_bufs)
{
	int ret = 0;
	struct spi_siwx917_data *data = dev->data;
	struct spi_context *ctx = &data->ctx;

	spi_context_lock(ctx, false, NULL, NULL, config);
	sl_si91x_gspi_set_slave_number(config->slave);
	spi_context_buffers_setup(ctx, tx_bufs, rx_bufs, 1);
	spi_context_cs_control(&data->ctx, true);
	while (spi_context_total_tx_len(ctx) > 0) {
		ret = spi_siwx917_transfer_next_packet(dev);
	}
	spi_context_release(ctx, ret);
	return ret;
}

static int spi_siwx917_release(const struct device *dev, const struct spi_config *config)
{
	struct spi_siwx917_data *data = dev->data;

	spi_context_unlock_unconditionally(&data->ctx);

	return 0;
}

static struct spi_driver_api spi_siwx917_driver_api = {
	.transceive = spi_siwx917_transceive,
	.release = spi_siwx917_release,
};

static void callback_event(uint32_t event)
{

}

static int spi_siwx917_init(const struct device *dev)
{
	struct spi_siwx917_data *data = dev->data;
	int ret = 0;

	sl_gspi_clock_config_t clock_config = {
		.soc_pll_mm_count_value = SOC_PLL_MM_COUNT_LIMIT,
		.intf_pll_500_control_value = INTF_PLL_500_CTRL_VALUE,
		.intf_pll_clock = INTF_PLL_CLK,
		.intf_pll_reference_clock = INTF_PLL_REF_CLK,
		.soc_pll_clock = SOC_PLL_CLK,
		.soc_pll_reference_clock = SOC_PLL_REF_CLK,
		.division_factor = DVISION_FACTOR,
	};
	sl_gspi_control_config_t config = {
		.bit_width = GSPI_BIT_WIDTH,
		.bitrate = GSPI_BITRATE,
		.clock_mode = SL_GSPI_MODE_0,
		.slave_select_mode = SL_GSPI_MASTER_HW_OUTPUT,
		.swap_read = SWAP_READ_DATA,
		.swap_write = SWAP_WRITE_DATA,
	};

	sl_si91x_gspi_configure_clock(&clock_config);
	sl_si91x_gspi_init(SL_GSPI_MASTER, &data->gspi_driver_handle);
	ret = sl_si91x_gspi_set_configuration(data->gspi_driver_handle, &config);
	if (ret != SL_STATUS_OK) {
		return ret;
	}
	ret = sl_si91x_gspi_register_event_callback(data->gspi_driver_handle, callback_event);
	if (ret != SL_STATUS_OK) {
		return ret;
	}
	spi_context_unlock_unconditionally(&data->ctx);
	return 0;
}

/* GSPI interrupt handler */
extern void IRQ046_Handler(void);
Z_ISR_DECLARE(46, ISR_FLAG_DIRECT, IRQ046_Handler, 0);

#define SIWX917_SPI_INIT(n)										\
	PINCTRL_DT_INST_DEFINE(n);									\
	static struct spi_siwx917_data spi_siwx917_data##n = {						\
		SPI_CONTEXT_INIT_LOCK(spi_siwx917_data##n, ctx),					\
		SPI_CONTEXT_INIT_SYNC(spi_siwx917_data##n, ctx)};					\
	static const struct spi_siwx917_config spi_siwx917_config##n = {				\
		.base = DT_INST_REG_ADDR(n),								\
		.size = DT_INST_REG_SIZE(n),								\
	};												\
	DEVICE_DT_INST_DEFINE(n, spi_siwx917_init, NULL, &spi_siwx917_data##n, &spi_siwx917_config##n,  \
			      POST_KERNEL, CONFIG_SPI_INIT_PRIORITY, &spi_siwx917_driver_api);

DT_INST_FOREACH_STATUS_OKAY(SIWX917_SPI_INIT)

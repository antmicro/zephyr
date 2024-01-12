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
#include <zephyr/device.h>
#include <zephyr/irq.h>
#include <stdint.h>

#include "rsi_rom_ulpss_clk.h"
#include "rsi_rom_egpio.h"
#include "rsi_rom_clks.h"
#include "sl_si91x_peripheral_i2c.h"

#define TX_ABRT_7B_ADDR_NOACK (1UL << 0)
#define MAX_7BIT_ADDRESS (1 << 7) - 1

#define READ_BIT BIT(8)
#define STOP_BIT BIT(9)

#define SIWX917_I2C_STATUS_OK                     0x01
#define SIWX917_I2C_STATUS_FAIL                   0x02

#define I2C_STANDARD_MODE_CLOCK_FREQUENCY    MHZ(32)
#define I2C_FAST_MODE_CLOCK_FREQUENCY        MHZ(32)
#define I2C_FAST_PLUS_MODE_CLOCK_FREQUENCY   MHZ(80)
#define I2C_HIGH_SPEED_MODE_CLOCK_FREQUENCY  MHZ(80)

#define REFERENCE_CLOCK_FREQUENCY            MHZ(32)
#define HIGH_SPEED_REFERENCE_CLOCK_FREQUENCY MHZ(40)

struct i2c_siwx917_config {
	const struct pinctrl_dev_config *pcfg;
	uint32_t base;
	void (*irq_config_func)(const struct device *dev);
	int (*pwr_func)(void);
};

struct i2c_siwx917_current_transfer {
	struct i2c_msg *msgs;
	uint8_t *curr_buf;
	uint8_t curr_len;
	uint8_t nr_msgs;
	uint8_t flags;
	uint8_t addr;
	uint8_t status;
};

struct i2c_siwx917_data {
	struct k_sem completion;
	struct i2c_siwx917_current_transfer transfer;
	I2C0_Type* i2c_periph;
};

static int i2c_siwx917_configure(const struct device *dev, uint32_t dev_config)
{
	struct i2c_siwx917_data *data = dev->data;
	uint32_t referece_clock = REFERENCE_CLOCK_FREQUENCY;
	sl_i2c_init_params_t i2c_config = {
		.mode = SL_I2C_LEADER_MODE,
	};

	switch (I2C_SPEED_GET(dev_config)) {
	case I2C_SPEED_DT:
		i2c_config.freq = I2C_STANDARD_MODE_CLOCK_FREQUENCY;
		i2c_config.clhr = SL_I2C_STANDARD_BUS_SPEED;
		break;
	case I2C_SPEED_STANDARD:
		i2c_config.freq = I2C_STANDARD_MODE_CLOCK_FREQUENCY;
		i2c_config.clhr = SL_I2C_STANDARD_BUS_SPEED;
		break;
	case I2C_SPEED_FAST:
		i2c_config.freq = I2C_FAST_MODE_CLOCK_FREQUENCY;
		i2c_config.clhr = SL_I2C_FAST_BUS_SPEED;
		break;
	case I2C_SPEED_FAST_PLUS:
		i2c_config.freq = I2C_FAST_PLUS_MODE_CLOCK_FREQUENCY;
		i2c_config.clhr = SL_I2C_FAST_PLUS_BUS_SPEED;
		break;
	case I2C_SPEED_HIGH:
		i2c_config.freq = I2C_HIGH_SPEED_MODE_CLOCK_FREQUENCY;
		i2c_config.clhr = SL_I2C_HIGH_BUS_SPEED;
		referece_clock = HIGH_SPEED_REFERENCE_CLOCK_FREQUENCY;
		break;
	default:
		return -EINVAL;
	}
	RSI_CLK_M4SocClkConfig(M4CLK, M4_ULPREFCLK, 0);
	RSI_CLK_SetSocPllFreq(M4CLK, i2c_config.freq, referece_clock);
	RSI_CLK_M4SocClkConfig(M4CLK, M4_SOCPLLCLK, 0);

	sl_si91x_i2c_init(data->i2c_periph, &i2c_config);
	return 0;
}

static void i2c_siwx917_read_msg(const struct device *dev, struct i2c_msg *msg, uint16_t addr) {
	struct i2c_siwx917_data *data = dev->data;

	sl_si91x_i2c_set_rx_threshold(data->i2c_periph, 0);
	sl_si91x_i2c_enable(data->i2c_periph);
	sl_si91x_i2c_control_direction(data->i2c_periph, SL_I2C_READ_MASK);
	sl_si91x_i2c_set_interrupts(data->i2c_periph, SL_I2C_EVENT_RECEIVE_FULL | SL_I2C_EVENT_TRANSMIT_ABORT | SL_I2C_EVENT_STOP_DETECT);
	sl_si91x_i2c_enable_interrupts(data->i2c_periph, 0);
}

static void i2c_siwx917_write_msg(const struct device *dev, struct i2c_msg *msg, uint16_t addr) {
	struct i2c_siwx917_data *data = dev->data;

	sl_si91x_i2c_set_tx_threshold(data->i2c_periph, 0);
	sl_si91x_i2c_enable(data->i2c_periph);
	sl_si91x_i2c_set_interrupts(data->i2c_periph, SL_I2C_EVENT_TRANSMIT_EMPTY | SL_I2C_EVENT_TRANSMIT_ABORT | SL_I2C_EVENT_STOP_DETECT);
	sl_si91x_i2c_enable_interrupts(data->i2c_periph, 0);
}

static void i2c_siwx917_transfer_msg(const struct device *dev, struct i2c_msg *msg, uint16_t addr)
{
	struct i2c_siwx917_data *data = dev->data;
	bool is_10bit_addr = addr > MAX_7BIT_ADDRESS;

	data->transfer.curr_buf = msg->buf;
	data->transfer.curr_len = msg->len;
	data->transfer.addr = addr;
	data->transfer.flags = msg->flags;
	data->transfer.status = SIWX917_I2C_STATUS_OK;

	sl_si91x_i2c_disable_interrupts(data->i2c_periph, 0);
	sl_si91x_i2c_disable(data->i2c_periph);
	sl_si91x_i2c_set_follower_address(data->i2c_periph, addr, is_10bit_addr);

	if (msg->flags & I2C_MSG_READ) {
		i2c_siwx917_read_msg(dev, msg, addr);
	} else {
		i2c_siwx917_write_msg(dev, msg, addr);
	}
}

static int i2c_siwx917_transfer(const struct device *dev, struct i2c_msg *msgs, uint8_t num_msgs,
			      uint16_t addr)
{
	struct i2c_siwx917_data *data = dev->data;
	int ret = 0;

	data->transfer.msgs = msgs;
	data->transfer.nr_msgs = num_msgs;

	for (uint8_t i = 0; i < num_msgs; ++i) {
		i2c_siwx917_transfer_msg(dev, &msgs[i], addr);
		k_sem_take(&data->completion, K_MSEC(500));
		if (data->transfer.status == SIWX917_I2C_STATUS_FAIL) {
			return -EIO;
		}
	}

	return ret;
}

static void handle_leader_transmit_irq(const struct device *dev)
{
	struct i2c_siwx917_data *data = dev->data;
	if (data->transfer.curr_len > 0) {
		if (data->transfer.curr_len == 1) {
			data->i2c_periph->IC_DATA_CMD = (uint32_t)*data->transfer.curr_buf | STOP_BIT;
			sl_si91x_i2c_clear_interrupts(data->i2c_periph, SL_I2C_EVENT_TRANSMIT_EMPTY);
		} else {
			sl_si91x_i2c_tx(data->i2c_periph, *data->transfer.curr_buf);
		}
		data->transfer.curr_buf++;
		data->transfer.curr_len--;
	} else {
		if (data->transfer.flags & I2C_MSG_STOP) {
			sl_si91x_i2c_stop_cmd(data->i2c_periph);
		}
		sl_si91x_i2c_clear_interrupts(data->i2c_periph, SL_I2C_EVENT_TRANSMIT_EMPTY);
	}
}

static void handle_leader_receive_irq(const struct device *dev)
{
	struct i2c_siwx917_data *data = dev->data;
	if (data->transfer.curr_len > 0) {
		*data->transfer.curr_buf = data->i2c_periph->IC_DATA_CMD_b.DAT;
		data->transfer.curr_buf++;
		data->transfer.curr_len--;
		if (data->transfer.curr_len == 0) {
			data->i2c_periph->IC_DATA_CMD = READ_BIT | STOP_BIT;
		}
		if (data->transfer.curr_len > 0) {
			data->i2c_periph->IC_DATA_CMD = READ_BIT;
		}
	}
	if (data->transfer.curr_len == 0) {
		sl_si91x_i2c_clear_interrupts(data->i2c_periph, SL_I2C_EVENT_RECEIVE_FULL);
	}
}

static int i2c_siwx917_init(const struct device *dev)
{
	int ret = 0;
	struct i2c_siwx917_data *data = dev->data;
	const struct i2c_siwx917_config *config = dev->config;
	data->i2c_periph = ((I2C0_Type*) config->base);
	config->pwr_func();
	k_sem_init(&data->completion, 0, 1);
	i2c_siwx917_configure(dev, I2C_SPEED_DT << I2C_SPEED_SHIFT);
	ret = pinctrl_apply_state(config->pcfg, PINCTRL_STATE_DEFAULT);

	return ret;
}

static void i2c_siwx917_irq(const struct device *dev)
{
	struct i2c_siwx917_data *data = dev->data;
	uint32_t status = 0;
	status = sl_si91x_i2c_get_pending_interrupts(data->i2c_periph);
	if (status & SL_I2C_EVENT_TRANSMIT_ABORT) {
		uint32_t tx_abrt = data->i2c_periph->IC_TX_ABRT_SOURCE;
		if (tx_abrt & (TX_ABRT_7B_ADDR_NOACK |
					SL_I2C_ABORT_7B_ADDRESS_NOACK |
					SL_I2C_ABORT_10B_ADDRESS1_NOACK |
					SL_I2C_ABORT_10B_ADDRESS2_NOACK |
					SL_I2C_ABORT_TX_DATA_NOACK)) {
			data->transfer.status = SIWX917_I2C_STATUS_FAIL;
			data->i2c_periph->IC_DATA_CMD_b.STOP = 0x1;
		}
		if (tx_abrt & SL_I2C_ABORT_GENERAL_CALL_NOACK) {
			uint32_t clear = data->i2c_periph->IC_CLR_GEN_CALL_b.CLR_GEN_CALL;
		}
		if (tx_abrt & SL_I2C_ABORT_GENERAL_CALL_READ) {
			uint32_t clear = data->i2c_periph->IC_CLR_GEN_CALL_b.CLR_GEN_CALL;
		}
		if (tx_abrt & SL_I2C_ABORT_HIGH_SPEED_ACK) {
		}
		if (tx_abrt & SL_I2C_ABORT_START_BYTE_ACK) {
		}
		if (tx_abrt & SL_I2C_ABORT_HIGH_SPEED_NO_RESTART) {
		}
		if (tx_abrt & SL_I2C_ABORT_START_BYTE_NO_RESTART) {
		}
		if (tx_abrt & SL_I2C_ABORT_10B_READ_NO_RESTART) {
		}
		if (tx_abrt & SL_I2C_ABORT_MASTER_DISABLED) {
		}
		if (tx_abrt & SL_I2C_ABORT_MASTER_ARBITRATION_LOST) {
		}
		if (tx_abrt & SL_I2C_ABORT_SLAVE_ARBITRATION_LOST) {
		}
		if (tx_abrt & SL_I2C_TX_TX_FLUSH_CNT) {
		}
		if (tx_abrt & SL_I2C_ABORT_USER_ABORT) {
		}
		if (tx_abrt & SL_I2C_ABORT_SDA_STUCK_AT_LOW) {
			data->i2c_periph->IC_ENABLE_b.SDA_STUCK_RECOVERY_ENABLE = 0x1;
		}
		uint32_t clear = data->i2c_periph->IC_CLR_INTR;
		sl_si91x_i2c_disable_interrupts(data->i2c_periph, SL_I2C_EVENT_TRANSMIT_EMPTY);
	}
	if (status & (SL_I2C_EVENT_SCL_STUCK_AT_LOW)) {
		uint32_t clear = data->i2c_periph->IC_CLR_INTR;
		return;
	}
	if (status & (SL_I2C_EVENT_MST_ON_HOLD)) {
		uint32_t clear = data->i2c_periph->IC_CLR_INTR;
		return;
	}
	if (status & (SL_I2C_EVENT_START_DETECT)) {
		uint32_t clear = data->i2c_periph->IC_CLR_START_DET_b.CLR_START_DET;
		return;
	}
	if (status & (SL_I2C_EVENT_STOP_DETECT)) {
		uint32_t clear     = data->i2c_periph->IC_CLR_STOP_DET_b.CLR_STOP_DET;
		uint32_t maskReg   = 0;
		maskReg            = data->i2c_periph->IC_INTR_MASK;
		data->i2c_periph->IC_INTR_MASK = (maskReg & (~SL_I2C_EVENT_RECEIVE_FULL));
		sl_si91x_i2c_disable_interrupts(data->i2c_periph, 0);
		k_sem_give(&data->completion);
		return;
	}
	if (status & (SL_I2C_EVENT_ACTIVITY_ON_BUS)) {
		uint32_t clear = data->i2c_periph->IC_CLR_ACTIVITY_b.CLR_ACTIVITY;
		return;
	}
	if (status & SL_I2C_EVENT_TRANSMIT_EMPTY) {
		handle_leader_transmit_irq(dev);
	}
	if (status & SL_I2C_EVENT_RECEIVE_FULL) {
		handle_leader_receive_irq(dev);
	}
	if (status & (SL_I2C_EVENT_RECEIVE_UNDER)) {
		uint32_t clear = data->i2c_periph->IC_CLR_RX_UNDER_b.CLR_RX_UNDER;
		return;
	}
	if (status & (SL_I2C_EVENT_RECEIVE_OVER)) {
		uint32_t clear = data->i2c_periph->IC_CLR_RX_OVER_b.CLR_RX_OVER;
		return;
	}
	if (status & (SL_I2C_EVENT_RECEIVE_DONE)) {
		sl_si91x_i2c_clear_interrupts(data->i2c_periph, SL_I2C_EVENT_RECEIVE_DONE);
		return;
	}
	if (status & (SL_I2C_EVENT_GENERAL_CALL)) {
		sl_si91x_i2c_clear_interrupts(data->i2c_periph, SL_I2C_EVENT_GENERAL_CALL);
		return;
	}
	if (status & (SL_I2C_EVENT_RESTART_DET)) {
		sl_si91x_i2c_clear_interrupts(data->i2c_periph, SL_I2C_EVENT_RESTART_DET);
		return;
	}
}

static int i2c_siwx917_recover_bus(const struct device *dev)
{
	struct i2c_siwx917_data *data = dev->data;

	sl_si91x_i2c_reset(data->i2c_periph);
	i2c_siwx917_configure(dev, I2C_SPEED_DT);
	return 0;
}

static struct i2c_driver_api i2c_siwx917_driver_api = {
	.configure = i2c_siwx917_configure,
	.transfer = i2c_siwx917_transfer,
	.recover_bus = i2c_siwx917_recover_bus,
};

#define SIWX917_I2C_DEFINE(n)								\
PINCTRL_DT_INST_DEFINE(n);								\
static int pwr_on_siwx917_i2c_##n(void)							\
{											\
	switch (DT_INST_REG_ADDR(n)) {							\
	case I2C0_BASE:									\
		RSI_PS_M4ssPeriPowerUp(M4SS_PWRGATE_ULP_EFUSE_PERI);			\
		break;									\
	case I2C1_BASE:									\
		RSI_PS_M4ssPeriPowerUp(M4SS_PWRGATE_ULP_EFUSE_PERI);			\
		break;									\
	case I2C2_BASE:									\
		RSI_PS_UlpssPeriPowerUp(ULPSS_PWRGATE_ULP_I2C);				\
		RSI_ULPSS_PeripheralEnable(ULPCLK, ULP_I2C_CLK, ENABLE_STATIC_CLK);	\
		break;									\
	default:									\
		return -1;								\
	}										\
	return 0;									\
}											\
static void i2c_siwx917_irq_config_##n(const struct device *dev)			\
{											\
	IRQ_CONNECT(DT_INST_IRQN(n),							\
		    DT_INST_IRQ(n, priority),						\
		    i2c_siwx917_irq, DEVICE_DT_INST_GET(n), 0);				\
											\
	irq_enable(DT_INST_IRQN(n));							\
}											\
static struct i2c_siwx917_data i2c_siwx917_data##n;					\
static const struct i2c_siwx917_config i2c_siwx917_config##n = {			\
	.pcfg = PINCTRL_DT_INST_DEV_CONFIG_GET(n),					\
	.irq_config_func = i2c_siwx917_irq_config_##n,					\
	.pwr_func = pwr_on_siwx917_i2c_##n,						\
	.base = DT_INST_REG_ADDR(n)							\
};											\
I2C_DEVICE_DT_INST_DEFINE(n, i2c_siwx917_init, NULL, &i2c_siwx917_data##n,		\
			&i2c_siwx917_config##n, POST_KERNEL, CONFIG_I2C_INIT_PRIORITY,	\
			&i2c_siwx917_driver_api);

DT_INST_FOREACH_STATUS_OKAY(SIWX917_I2C_DEFINE)

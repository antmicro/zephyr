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

#define CONFIG_ADV7535_THREAD_STACK_SIZE 1024 // TODO: Add kconfig for this

static K_KERNEL_STACK_DEFINE(drv_stack, CONFIG_ADV7535_THREAD_STACK_SIZE);
static struct k_thread drv_stack_data;

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
	struct gpio_dt_spec dt_int;
};

struct adv7535_data {
	struct gpio_callback int_gpio_cb;
	struct k_sem irq_sem;
	enum connection_state conn_state;
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

static int adv7535_write_bit(const struct device *dev, uint8_t reg, uint8_t bit, uint8_t val)
{
	int ret;
	uint8_t buf;

	ret = adv7535_read(dev, reg, &buf);
	if (ret) {
		return ret;
	}

	buf &= ~bit;
	buf |= val;

	return adv7535_write(dev, reg, buf);
}

static int adv7535_read_bit(const struct device *dev, uint8_t reg, uint8_t bit, uint8_t *buf)
{
	int ret;
	uint8_t byte_buf;

	ret = adv7535_read(dev, reg, &byte_buf);
	if (ret) {
		return ret;
	}

	byte_buf &= bit;
	*buf = (bool)(byte_buf);

	return 0;
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

static int adv7535_enable_interrupts(const struct device *dev)
{
	/* Enable hdmi connect/disconnect detection */
	return adv7535_write(dev, ADV7535_REG_INT_ENABLE_0,ADV7535_INT_0_MONITOR_SENSE);
}

static int adv7535_dsi_power_on(const struct device *dev)
{
	const struct adv7535_config *config = dev->config;
	int ret = 0;
	uint8_t tmp;

	/* This function is a part of ADV7533_Configure in STM driver
	 * And is pretty much 1 to 1 with adv7533_dsi_power_on from the Linux driver
	 */

	/* set num of dsi lines */
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
		/* Disable internal timing generator */
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
	// TODO: Make the test pattern configurable in the DTS
	// test-pattern = <0>; = Off (Default)
	// test-pattern = <1>; = Color Bars
	// test-pattern = <2>; = Grayscale gradient

	// adv7535_write_cec(dev, 0x16, 0x00); // Maybe needed? Works without it

	// Color bars
	adv7535_write_cec(dev, 0x55, 0x80);

	// Grayscale gradient
	// adv7535_write_cec(dev, 0x55, 0xA0);

	// A magic value from from the ST sample (linked at the top of the file)
	adv7535_write_cec(dev, 0xAF, 0x16);

	return 0;
}

static int adv7535_disable_test_pattern(const struct device *dev)
{
	adv7535_write_cec(dev, 0x55, 0x00);

	return 0;
}

static int adv7535_configure(const struct device *dev)
{
	const struct adv7535_config *config = dev->config;

	uint16_t hsync_end, hsync_start, hdisplay, htotal, vsync_end, vsync_start, vdisplay, vtotal;
	uint32_t hsw, hfp, hbp, vsw, vfp, vbp;

	static const uint8_t clock_div_by_lanes[] = { 6, 4, 3 };	/* 2, 3, 4 lanes */

	// Set HDMI/DVI Mode (1 = HDMI; 0 = DVI)
	// Works only with DVI
	adv7535_write_bit(dev, 0xaf, BIT(1), 0);

	// These are defaults
	// adv7535_write_bit(dev, 0xaf, BIT(7), 0);
	// adv7535_write_bit(dev, 0xaf, BIT(0), 0);

	// Linux driver sets high/low hsync and vsync polarity in adv7511_mode_set,
	// our dsi host in dts has polarity set to high which is the default in adv

	hsync_end   = 752;
	hsync_start = 656;
	hdisplay    = 640;
	htotal      = 800;
	vsync_end   = 492;
	vsync_start = 490;
	vdisplay    = 480;
	vtotal      = 525;

	hsw = hsync_end - hsync_start;
	hfp = hsync_start - hdisplay;
	hbp = htotal - hsync_end;
	vsw = vsync_end - vsync_start;
	vfp = vsync_start - vdisplay;
	vbp = vtotal - vsync_end;


	// Linux adv7533_dsi_config_timing_gen() packs each timing value as:
	//   high byte: timing >> 4
	//   low byte:  (timing << 4) & 0xff

	/* set pixel clock divider mode */
	adv7535_write_cec(dev, 0x16, clock_div_by_lanes[config->num_of_lanes - 2] << 3);


	/* horizontal porch params */
	adv7535_write_cec(dev, 0x28, htotal >> 4);
	adv7535_write_cec(dev, 0x29, (htotal << 4) & 0xff);
	adv7535_write_cec(dev, 0x2a, hsw >> 4);
	adv7535_write_cec(dev, 0x2b, (hsw << 4) & 0xff);
	adv7535_write_cec(dev, 0x2c, hfp >> 4);
	adv7535_write_cec(dev, 0x2d, (hfp << 4) & 0xff);
	adv7535_write_cec(dev, 0x2e, hbp >> 4);
	adv7535_write_cec(dev, 0x2f, (hbp << 4) & 0xff);

	/* vertical porch params */
	adv7535_write_cec(dev, 0x30, vtotal >> 4);
	adv7535_write_cec(dev, 0x31, (vtotal << 4) & 0xff);
	adv7535_write_cec(dev, 0x32, vsw >> 4);
	adv7535_write_cec(dev, 0x33, (vsw << 4) & 0xff);
	adv7535_write_cec(dev, 0x34, vfp >> 4);
	adv7535_write_cec(dev, 0x35, (vfp << 4) & 0xff);
	adv7535_write_cec(dev, 0x36, vbp >> 4);
	adv7535_write_cec(dev, 0x37, (vbp << 4) & 0xff);

	return 0;
}

static int adv7535_power_up(const struct device *dev)
{
	int ret = 0;
	uint8_t pd_bit;

	ret = adv7535_read_bit(dev, ADV7535_REG_POWER, ADV7535_POWER_DOWN, &pd_bit);
	if (ret) {
		return ret;
	}

	if (pd_bit) {
		ret = adv7535_write_bit(dev, ADV7535_REG_POWER, ADV7535_POWER_DOWN, 0);
	} else {
		LOG_INF("Powering up ADV7535, while it is already powered up");
	}

	adv7535_enable_interrupts(dev);
	adv7535_dsi_power_on(dev);
	adv7535_set_cec_fixed_registers(dev);

	adv7535_configure(dev);

	// adv7535_enable_test_pattern(dev);
	adv7535_disable_test_pattern(dev);

	return ret;
}

static int adv7535_power_down(const struct device *dev)
{
	/* TODO: Verify this does not need to do more things */

	int ret = 0;
	uint8_t pd_bit;

	ret = adv7535_read_bit(dev, ADV7535_REG_POWER, ADV7535_POWER_DOWN, &pd_bit);
	if (ret) {
		return ret;
	}

	if (pd_bit) {
		LOG_INF("Powering down ADV7535, while it is already powered down");
	} else {
		ret = adv7535_write_bit(dev, ADV7535_REG_POWER, ADV7535_POWER_DOWN, ADV7535_POWER_DOWN);
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

	mdev.mode_flags = MIPI_DSI_MODE_VIDEO | MIPI_DSI_MODE_VIDEO_SYNC_PULSE
			  | MIPI_DSI_MODE_EOT_PACKET | MIPI_DSI_MODE_VIDEO_HSE;

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

static int adv7535_configure_rst_gpio(const struct device *dev)
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

static int adv7535_handle_monitor_sense(const struct device *dev, uint8_t int_0_reg)
{
	struct adv7535_data *data = dev->data;

	int ret;
	uint8_t monitor_sense_state;
	enum connection_state new_conn_state;
	bool is_monitor_sense = int_0_reg & ADV7535_INT_0_MONITOR_SENSE;

	if (!is_monitor_sense){
		/* No connect/disconnect event */
		return 0;
	}

	ret = adv7535_read_bit(dev, ADV7535_REG_PORT_STATE, ADV7535_MONITOR_SENSE_STATE, &monitor_sense_state);
	if (ret) {
		return ret;
	}
	new_conn_state = monitor_sense_state ? CONNECTED : DISCONNECTED;

	// TODO: When probing initially for display also call power up etc
	// TODO: Then add a if here to check if state changed DISCONNECT -> CONNECT
	if (new_conn_state == CONNECTED) {
		adv7535_power_up(dev);
	}
	// TODO: Handle DISCONNECT

	if (data->conn_state != new_conn_state) {
		data->conn_state = new_conn_state;
		LOG_DBG("%s detected", new_conn_state == CONNECTED ? "Connect" : "Disconnect");
	}

	return 0;
}

static void adv7535_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	struct device *dev = p1;
	const struct adv7535_config *config = dev->config;
	struct adv7535_data *data = dev->data;

	LOG_DBG("ADV7535 Thread started");

	while (true) {
		uint8_t int_0_reg, int_1_reg;
		int ret;

		k_sem_take(&data->irq_sem, K_FOREVER);

		LOG_DBG("Interrupt!");

		do {
			adv7535_read(dev, ADV7535_REG_INT_0, &int_0_reg);
			adv7535_read(dev, ADV7535_REG_INT_1, &int_1_reg);

			ret = adv7535_handle_monitor_sense(dev, int_0_reg);

			/* Clear all interrupts */
			adv7535_write(dev, ADV7535_REG_INT_0, int_0_reg);
			adv7535_write(dev, ADV7535_REG_INT_1, int_1_reg);

		/* We check interrupt gpio again to make sure a new interrupt did not occur,
		 * while we were handling the current one.
		 *
		 * ADV7535 signals a presence of a interrupt by pulling interrupt pin low,
		 * it goes to high only while all interrupts have been resolved.
		 *
		 * Since not all boards support GPIO_INT_LEVEL_LOW or GPIO_INT_LEVEL_ACTIVE,
		 * we use GPIO_INT_EDGE_TO_ACTIVE and just recheck interrupt gpio state.
		 */
		} while (gpio_pin_get_dt(&config->dt_int));
	}
}

static void adv7535_int_gpio_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	struct adv7535_data *data = CONTAINER_OF(cb, struct adv7535_data, int_gpio_cb);

	k_sem_give(&data->irq_sem);
}

static int adv7535_remove_int_callback(const struct device *dev)
{
	const struct adv7535_config *config = dev->config;
	struct adv7535_data *data = dev->data;

	return gpio_remove_callback_dt(&config->dt_int, &data->int_gpio_cb);
}

static int adv7535_configure_int_gpio(const struct device *dev)
{
	const struct adv7535_config *config = dev->config;
	struct adv7535_data *data = dev->data;
	int ret = 0;

	gpio_init_callback(&data->int_gpio_cb, adv7535_int_gpio_cb,
			  BIT(config->dt_int.pin));

	ret = gpio_add_callback_dt(&config->dt_int, &data->int_gpio_cb);
	if (ret) {
		goto error;
	}

	ret = gpio_pin_configure_dt(&config->dt_int, GPIO_INPUT);
	if (ret) {
		goto error;
	}

	ret = gpio_pin_interrupt_configure_dt(&config->dt_int, GPIO_INT_EDGE_TO_ACTIVE);
	if (ret) {
		goto error;
	}

	return 0;

error:
	adv7535_remove_int_callback(dev);
	return ret;
}

static int adv7535_disable_and_clear_all_interrupts(const struct device *dev)
{
	const struct adv7535_config *config = dev->config;
	struct adv7535_data *data = dev->data;
	int ret;

	uint8_t int_enable_regs[] = {
		ADV7535_REG_CEC_INT_ENABLE,
		ADV7535_REG_INT_ENABLE_0,
		ADV7535_REG_INT_ENABLE_1,
	};

	uint8_t int_regs[] = {
		ADV7535_REG_INT_0,
		ADV7535_REG_INT_1,
		ADV7535_REG_CEC_INT
	};

	ARRAY_FOR_EACH(int_enable_regs, i) {
		ret = adv7535_write(dev, int_enable_regs[i], 0);
		if (ret) {
			return ret;
		}
	}

	ARRAY_FOR_EACH(int_regs, i) {
		ret = adv7535_write(dev, int_regs[i], 0xff);
		if (ret) {
			return ret;
		}
	}

	return 0;
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

static int adv7535_set_data(const struct device *dev)
{
	struct adv7535_data *data = dev->data;
	int ret;
	uint8_t monitor_sense_state;

	ret = adv7535_read_bit(dev, ADV7535_REG_PORT_STATE, ADV7535_MONITOR_SENSE_STATE, &monitor_sense_state);
	if (ret) {
		return ret;
	}

	data->conn_state = monitor_sense_state ? CONNECTED : DISCONNECTED;

	return 0;
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

	ret = adv7535_configure_rst_gpio(dev);
	if (ret) {
		LOG_ERR("Failed configuring reset GPIO");
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

	ret = adv7535_disable_and_clear_all_interrupts(dev);
	if (ret) {
		LOG_ERR("Failed disabling interrupts");
		return ret;
	}

	ret = adv7535_configure_int_gpio(dev);
	if (ret) {
		LOG_ERR("Failed configuring interrupt GPIO");
		goto error;
	}

	ret = adv7535_enable_interrupts(dev);
	if (ret) {
		LOG_ERR("Failed enabling interrupts");
		goto error;
	}

	ret = adv7535_set_data(dev);
	if (ret) {
		LOG_ERR("Failed to set adv7535 data values");
		goto error;
	}

	/* Is adv7535_power_down/up call needed here? */
	// adv7535_power_down(dev);
	adv7535_power_up(dev);

	ret = adv7535_set_fixed_registers(dev);
	if (ret){
		LOG_ERR("Failed to set fixed registers: %d", ret);
		goto error;
	}

	/* Disable all packets */
	adv7535_write(dev, ADV7535_REG_ENABLE_0, 0);
	adv7535_write(dev, ADV7535_REG_ENABLE_1, 0);

	ret = adv7535_set_cec_fixed_registers(dev);
	if (ret){
		LOG_ERR("Failed to set CEC fixed registers: %d", ret);
		goto error;
	}

	/* Enable CEC */
	adv7535_write(dev, ADV7535_REG_CEC_POWER_DOWN, ADV7535_CEC_POWER_DOWN);

	ret = adv7535_attach_to_mipi_dsi_host(dev);
	if (ret) {
		LOG_ERR("Failed to attach to MIPI DSI host: %d", ret);
		goto error;
	}

	// TODO: Evaluated what priority should this thraed have
	k_thread_create(&drv_stack_data, drv_stack, K_KERNEL_STACK_SIZEOF(drv_stack),
			adv7535_thread, (void*)dev, NULL, NULL,
			K_PRIO_COOP(2), 0, K_NO_WAIT);
	k_thread_name_set(&drv_stack_data, "adv7535");

	// TODO: Add general info here like i2c addresses, channel etc.
	adv7535_read(dev, 0x00, &revision);
	LOG_DBG("ADV7535 initialized. Chip Revision: %d", revision);

	return 0;

error:
	adv7535_remove_int_callback(dev);
	return ret;
}

#define ADV7535_IS_PD_ACTIVE_LOW(id) (DT_INST_GPIO_FLAGS(id, pd_gpios) & GPIO_ACTIVE_LOW)

#define ADV7535_IS_PD_AND_ADDR_VALID(id)                                      \
	((DT_INST_REG_ADDR(id) == 0x39 && !(ADV7535_IS_PD_ACTIVE_LOW(id))) || \
	(DT_INST_REG_ADDR(id) == 0x3d && (ADV7535_IS_PD_ACTIVE_LOW(id))))     \

#define ADV7535_VALIDATE_PD_AND_ADDR(id)                                      \
	IF_ENABLED(DT_INST_NODE_HAS_PROP(id, pd_gpios),                       \
	(BUILD_ASSERT((ADV7535_IS_PD_AND_ADDR_VALID(id)),                     \
		"ADV7535 I2C address does not match pd-gpios polarity. "      \
		"0x39 requres active high, 0x3d requres active low."          \
	      ))                                                              \
	);

#define ADV7535_DEFINE(id)                                                                                \
	static const struct adv7535_config config_##id = {                                                \
		.mipi_dsi_host = DEVICE_DT_GET(DT_INST_PHANDLE(id, mipi_dsi)),                            \
		.channel = DT_INST_PROP(id, dsi_channel),                                                 \
		.num_of_lanes = DT_INST_PROP_BY_IDX(id, data_lanes, 0),                                   \
		.i2c_conf = {                                                                             \
			.i2c = I2C_DT_SPEC_INST_GET(id),                                                  \
			.edid_addr = DT_INST_PROP_OR(id, edid_addr, ADV7535_I2C_EDID_ADDR_DEFAULT),       \
			.packet_addr = DT_INST_PROP_OR(id, packet_addr, ADV7535_I2C_PACKET_ADDR_DEFAULT), \
			.cec_addr = DT_INST_PROP_OR(id, cec_addr, ADV7535_I2C_CEC_ADDR_DEFAULT),          \
			.fixed_addr = DT_INST_PROP_OR(id, fixed_addr, ADV7535_I2C_FIXED_ADDR_DEFAULT),    \
		},                                                                                        \
		.dt_pd = GPIO_DT_SPEC_INST_GET_OR(id, pd_gpios, {0}),                                     \
		.dt_int = GPIO_DT_SPEC_INST_GET(id, int_gpios)                                            \
	};                                                                                                \
	static struct adv7535_data data_##id = {                                                          \
		.pixel_format = DT_INST_PROP(id, pixel_format),                                           \
		.irq_sem = Z_SEM_INITIALIZER(data_##id.irq_sem, 0, 1)                                     \
	};                                                                                                \
	DEVICE_DT_INST_DEFINE(id, adv7535_init, NULL, &data_##id, &config_##id,                           \
			      POST_KERNEL, CONFIG_DISPLAY_INIT_PRIORITY, NULL);                           \
	ADV7535_VALIDATE_PD_AND_ADDR(id)                                                                  \

DT_INST_FOREACH_STATUS_OKAY(ADV7535_DEFINE)

/*
 * Copyright (c) 2024 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/input/input.h>
#include <zephyr/drivers/display.h>
#include <zephyr/sys/util.h>
#include <zephyr/usb/usbh.h>

LOG_MODULE_REGISTER(main, LOG_LEVEL_DBG);

USBH_CONTROLLER_DEFINE(uhs_ctx, DEVICE_DT_GET(DT_NODELABEL(zephyr_uhc0)));

#define ANSI_COLOR_GREEN "\x1b[92m"
#define ANSI_COLOR_RESET "\x1b[0m"

#ifdef CONFIG_SAMPLE_COLORED_OUTPUT
#define HIGHLIGHT(text) ANSI_COLOR_GREEN text ANSI_COLOR_RESET
#else
#define HIGHLIGHT(text) text
#endif

#define SCREEN_WIDTH_TO_CROSS_DIM 25

#if !DT_NODE_EXISTS(DT_CHOSEN(zephyr_display))
#error "Unsupported board: zephyr,display is not assigned"
#endif

#define WIDTH     (DT_PROP(DT_CHOSEN(zephyr_display), width))
#define HEIGHT    (DT_PROP(DT_CHOSEN(zephyr_display), height))
#define CROSS_DIM (WIDTH / SCREEN_WIDTH_TO_CROSS_DIM)

#define PIXEL_FORMAT (DT_PROP_OR(DT_CHOSEN(zephyr_display), pixel_format, PIXEL_FORMAT_ARGB_8888))
/* #define BPP          ((DISPLAY_BITS_PER_PIXEL(PIXEL_FORMAT)) / BITS_PER_BYTE) */
#define BPP          2

#define BUFFER_SIZE  (CROSS_DIM * CROSS_DIM * BPP)
#define REFRESH_RATE 10

static const struct device *const display_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_display));
static struct display_buffer_descriptor buf_desc = {
	.buf_size = BUFFER_SIZE, .pitch = CROSS_DIM, .width = CROSS_DIM, .height = CROSS_DIM};

static uint8_t buffer_cross[BUFFER_SIZE];
static const uint8_t buffer_cross_empty[BUFFER_SIZE];
static struct k_sem sync;

static bool last_pressed;
static struct {
	int32_t x;
	int32_t y;
	bool pressed;
} touch_point, touch_point_drawn;

static size_t clamp_cursor_pos(int32_t pos, int32_t max_val)
{
	return CLAMP(pos, CROSS_DIM / 2, max_val - CROSS_DIM / 2);
}

static void touch_event_callback(struct input_event *evt, void *user_data)
{
	if (evt->code == INPUT_REL_X) {
		touch_point.x = clamp_cursor_pos(touch_point.x + evt->value, WIDTH);
	}
	if (evt->code == INPUT_REL_Y) {
		touch_point.y = clamp_cursor_pos(touch_point.y + evt->value, HEIGHT);
	}
	if (evt->code == INPUT_BTN_LEFT) {
		touch_point.pressed = evt->value;
	}
	if (evt->sync) {
		k_sem_give(&sync);
	}
}
INPUT_CALLBACK_DEFINE(NULL, touch_event_callback, NULL);

static int clear_screen(void)
{
	int x;
	int y;
	int ret;

	for (x = 0; x < WIDTH; x += CROSS_DIM) {
		for (y = 0; y < HEIGHT; y += CROSS_DIM) {
			struct display_buffer_descriptor ddesc = buf_desc;
			uint16_t rem_w = WIDTH - x;
			uint16_t rem_h = HEIGHT - y;

			ddesc.width = MIN(buf_desc.width, rem_w);
			ddesc.height = MIN(buf_desc.height, rem_h);
			ddesc.buf_size = ddesc.width * ddesc.height * BPP;

			ret = display_write(display_dev, x, y, &ddesc, buffer_cross_empty);
			if (ret < 0) {
				LOG_ERR("Failed to write to display (error %d)", ret);
				return ret;
			}
		}
	}

	return 0;
}

static void fill_cross_buffer(void)
{
	int i;
	int x;
	int y;
	int index;

	for (i = 0; i < BPP; i++) {
		for (x = 0; x < CROSS_DIM; x++) {
			index = BPP * (CROSS_DIM / 2 * CROSS_DIM + x);
			buffer_cross[index + i] = -1;
		}
		for (y = 0; y < CROSS_DIM; y++) {
			index = BPP * (y * CROSS_DIM + CROSS_DIM / 2);
			buffer_cross[index + i] = -1;
		}
	}
}

static int get_draw_position(int value, int upper_bound)
{
	if (value < CROSS_DIM / 2) {
		return 0;
	}

	if (value + CROSS_DIM / 2 > upper_bound) {
		return upper_bound - CROSS_DIM;
	}

	return value - CROSS_DIM / 2;
}

static int init_usb(void)
{
	int err = 0;

	err = usbh_init(&uhs_ctx);
	if (err == -EALREADY) {
		LOG_ERR("host: USB host already initialized");
	} else if (err) {
		LOG_ERR("host: Failed to initialize %d", err);
	} else {
		LOG_INF("host: USB host initialized");
	}

	return err;
}

static int init_display(void)
{
	int err = 0;

	if (!device_is_ready(display_dev)) {
		LOG_ERR("Device %s not found. Aborting sample.", display_dev->name);
		return -1;
	}

	if (BPP == 0 || BPP > 4) {
		LOG_ERR("Unsupported BPP=%d", BPP);
		return -1;
	}
	fill_cross_buffer();
	err = display_blanking_off(display_dev);
	if (err < 0 && err != -ENOSYS) {
		LOG_ERR("Failed to turn blanking off (error %d)", err);
		return -1;
	}

	err = clear_screen();
	if (err < 0) {
		LOG_ERR("Failed to clear the screen");
		return -1;
	}

	return err;
}

int main(void)
{
	int ret;

	ret = init_usb();
	if (ret) {
		LOG_ERR("Failed to initialize the USB host stack");
		return 0;
	}

	ret = init_display();
	if (ret) {
		LOG_ERR("Failed to initialize the display");
		return 0;
	}

	touch_point_drawn.x = CROSS_DIM / 2;
	touch_point_drawn.y = CROSS_DIM / 2;
	/* touch_point.x = -1; */
	/* touch_point.y = -1; */
	touch_point.x = 1;
	touch_point.y = 1;

	k_sem_init(&sync, 0, 1);

	while (1) {
		k_msleep(REFRESH_RATE);
		k_sem_take(&sync, K_FOREVER);

		LOG_INF_RATELIMIT_RATE(100, "Cursor X: %d; Y: %d", touch_point.x, touch_point.y);

		if (last_pressed != touch_point.pressed) {
			LOG_INF(HIGHLIGHT("Left") " button " HIGHLIGHT("%s") " at x:%d y:%d",
				touch_point.pressed ? "pressed" : "let go", touch_point.x,
				touch_point.y);
			last_pressed = touch_point.pressed;
		}

		ret = display_write(display_dev, get_draw_position(touch_point_drawn.x, WIDTH),
				    get_draw_position(touch_point_drawn.y, HEIGHT), &buf_desc,
				    buffer_cross_empty);
		if (ret < 0) {
			LOG_ERR("Failed to write to display (error %d)", ret);
			return 0;
		}

		ret = display_write(display_dev, get_draw_position(touch_point.x, WIDTH),
				    get_draw_position(touch_point.y, HEIGHT), &buf_desc,
				    buffer_cross);
		if (ret < 0) {
			LOG_ERR("Failed to write to display (error %d)", ret);
			return 0;
		}

		touch_point_drawn.x = touch_point.x;
		touch_point_drawn.y = touch_point.y;
	}
	return 0;
}

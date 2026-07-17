/*
 * Copyright (c) 2024 Open Pixel Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/display.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(main, LOG_LEVEL_DBG);

#define DISPLAY_NODE   DT_CHOSEN(zephyr_display)
#define DISPLAY_WIDTH  DT_PROP(DISPLAY_NODE, width)
#define DISPLAY_HEIGHT DT_PROP(DISPLAY_NODE, height)
#define DSI_BASE       DT_REG_ADDR(DT_NODELABEL(mipi_dsi))
#define LTDC_BASE      DT_REG_ADDR(DT_NODELABEL(ltdc))
#define RGB888_BYTES_PER_PIXEL 3U
#define TEST_COLOR_COUNT 8U

static const struct device *const display = DEVICE_DT_GET(DISPLAY_NODE);
static uint8_t line_buffer[DISPLAY_WIDTH * RGB888_BYTES_PER_PIXEL];

/* STM32 LTDC RGB888 framebuffer byte order: B, G, R. */
static const uint8_t test_colors[TEST_COLOR_COUNT][RGB888_BYTES_PER_PIXEL] = {
	{ 0xff, 0xff, 0xff }, /* source x   0- 79: white */
	{ 0x00, 0xff, 0xff }, /* source x  80-159: yellow */
	{ 0xff, 0xff, 0x00 }, /* source x 160-239: cyan */
	{ 0x00, 0xff, 0x00 }, /* source x 240-319: green */
	{ 0xff, 0x00, 0xff }, /* source x 320-399: magenta */
	{ 0x00, 0x00, 0xff }, /* source x 400-479: red */
	{ 0xff, 0x00, 0x00 }, /* source x 480-559: blue */
	{ 0x80, 0x80, 0x80 }, /* source x 560-639: gray */
};

int main(void)
{
	LOG_DBG("Test 1");
	struct display_buffer_descriptor descriptor = {
		.buf_size = sizeof(line_buffer),
		.width = DISPLAY_WIDTH,
		.height = 1,
		.pitch = DISPLAY_WIDTH,
		.frame_incomplete = false,
	};
	struct display_capabilities capabilities;
	int ret;

	if (!device_is_ready(display)) {
		LOG_ERR("Display device %s is not ready", display->name);
		return 0;
	}

	LOG_DBG("Test 2");
	display_get_capabilities(display, &capabilities);
	if (capabilities.current_pixel_format != PIXEL_FORMAT_RGB_888) {
		LOG_ERR("Expected RGB888, got pixel format 0x%x",
			capabilities.current_pixel_format);
		return 0;
	}

	LOG_DBG("Test 3");
	memset(line_buffer, 0x00, sizeof(line_buffer));
	for (uint16_t y = 0; y < DISPLAY_HEIGHT; y++) {
		ret = display_write(display, 0, y, &descriptor, line_buffer);
		if (ret < 0) {
			LOG_ERR("Failed to clear display row %u: %d", y, ret);
			return 0;
		}
	}

	/* Draw eight identifiable 80-pixel sections on the single test row. */
	for (uint16_t x = 0; x < DISPLAY_WIDTH; x++) {
		uint8_t color = (x * TEST_COLOR_COUNT) / DISPLAY_WIDTH;
		uint32_t offset = x * RGB888_BYTES_PER_PIXEL;

		line_buffer[offset] = test_colors[color][0];
		line_buffer[offset + 1] = test_colors[color][1];
		line_buffer[offset + 2] = test_colors[color][2];
	}

	LOG_DBG("Test 4");
	ret = display_write(display, 0, DISPLAY_HEIGHT / 2, &descriptor, line_buffer);
	if (ret < 0) {
		LOG_ERR("Failed to draw horizontal line: %d", ret);
		return 0;
	}

	LOG_DBG("Test 6");
	LOG_INF("Drew line at y=%u", DISPLAY_HEIGHT / 2);

	return 0;
}

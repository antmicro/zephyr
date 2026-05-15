/*
 * Copyright (c) 2024 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/input/input.h>
#include <zephyr/usb/usbh.h>

#include "keys.h"

#define ANSI_COLOR_GREEN "\x1b[92m"
#define ANSI_COLOR_RESET "\x1b[0m"

#ifdef CONFIG_SAMPLE_COLORED_OUTPUT
#define HIGHLIGHT(text) ANSI_COLOR_GREEN text ANSI_COLOR_RESET
#else
#define HIGHLIGHT(text) text
#endif

LOG_MODULE_REGISTER(main, LOG_LEVEL_DBG);

USBH_CONTROLLER_DEFINE(uhs_ctx, DEVICE_DT_GET(DT_NODELABEL(zephyr_uhc0)));

static const struct device *usbh_hid_dev;

static const char *input_to_key_name(uint16_t key_code)
{
	if (key_code >= ARRAY_SIZE(input_to_key_name_map)) {
		return 0;
	}
	return input_to_key_name_map[key_code];
}

static void mouse_evt_handler(struct input_event *evt)
{
	switch (evt->code) {
	case INPUT_BTN_LEFT:
		LOG_INF(HIGHLIGHT("Left") " button " HIGHLIGHT("%s"),
			evt->value ? "pressed" : "let go");
		break;
	case INPUT_BTN_MIDDLE:
		LOG_INF(HIGHLIGHT("Middle") " button " HIGHLIGHT("%s"),
			evt->value ? "pressed" : "let go");
		break;
	case INPUT_BTN_RIGHT:
		LOG_INF(HIGHLIGHT("Right") " button " HIGHLIGHT("%s"),
			evt->value ? "pressed" : "let go");
		break;
	case INPUT_REL_X:
	case INPUT_REL_Y:
		LOG_INF("Mouse moved in " HIGHLIGHT("%c") " axis by " HIGHLIGHT("%d"),
			evt->code == INPUT_REL_X ? 'X' : 'Y', evt->value);
		break;
	}
}

static void kbd_evt_handler(struct input_event *evt)
{
	const char *name = input_to_key_name(evt->code);

	if (name) {
		LOG_INF("Key " HIGHLIGHT("%s") " was " HIGHLIGHT("%s"), name,
			evt->value ? "pressed" : "released");
	}
}

static void input_cb(struct input_event *evt, void *user_data)
{
	ARG_UNUSED(user_data);

	/* Check if the event is from the desired device */
	if (evt->dev != usbh_hid_dev) {
		return;
	}

	if (evt->type == INPUT_EV_REL || evt->code == INPUT_BTN_LEFT ||
	    evt->code == INPUT_BTN_MIDDLE || evt->code == INPUT_BTN_RIGHT) {
		mouse_evt_handler(evt);
	} else {
		kbd_evt_handler(evt);
	}
}
INPUT_CALLBACK_DEFINE(NULL, input_cb, NULL);

int main(void)
{
	int err;

	/*
	 * HID Boot devices are named:
	 * usbh_hid_boot_0,
	 * usbh_hid_boot_1,
	 * ...,
	 * usbh_hid_boot_(CONFIG_USBH_HID_BOOT_INSTANCES_COUNT-1)
	 */
	usbh_hid_dev = device_get_binding("usbh_hid_boot_0");

	err = usbh_init(&uhs_ctx);
	if (err == -EALREADY) {
		LOG_ERR("host: USB host already initialized");
	} else if (err) {
		LOG_ERR("host: Failed to initialize %d", err);
	} else {
		LOG_INF("host: USB host initialized");
	}

	return 0;
}

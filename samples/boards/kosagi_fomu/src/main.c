/*
 * Copyright (c) 2022 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <device.h>
#include <errno.h>
#include <drivers/led.h>
#include <sys/util.h>
#include <zephyr.h>

void main(void)
{
	const struct device *led_dev = DEVICE_DT_GET_ANY(fomu_sbled);

	for (int i = 0;; i++) {
		led_off(led_dev, 0);
		led_off(led_dev, 1);
		led_off(led_dev, 2);

		led_on(led_dev, i % 3);

		k_msleep(1000);
	}
}

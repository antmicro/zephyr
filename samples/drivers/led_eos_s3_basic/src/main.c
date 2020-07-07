/*
 * ==========================================================
 *
 *    Copyright (C) 2020 QuickLogic Corporation
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *		http://www.apache.org/licenses/LICENSE-2.0
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 *    File      : main.c
 *    Purpose   : This file has simple prints.
 *                No other configuration needs to be done here
 *
 * ===========================================================
 */

#include <zephyr.h>
#include <device.h>
#include <soc.h>

void main(void)
{
	printk("\n\n");
	printk("##########################\n");
	printk("Quicklogic Open Platform 2.0\n");
	printk("SW Version: ");
	printk(" OP2-QuickFeather-led-eos-s3-basic sample");
	printk("\n");
	printk(__DATE__ " " __TIME__ "\n");
	printk("##########################\n\n");
}

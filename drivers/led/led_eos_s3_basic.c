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
 *    File      : led_eos_s3_basic.c
 *    Purpose   : This is the driver for basic LED controller IP.
 *
 *
 * ===========================================================
 *
 */

#include <zephyr.h>
#include <soc.h>
#include <fpga_loader.h>
#include "eos_s3_led_basic_ip.h"
#include "eos_s3_led_config.h"

static void config_ios(void)
{
	eos_s3_io_mux(FPGA_LED0_PAD, FPGA_LED0_PAD_CFG);
	eos_s3_io_mux(FPGA_LED1_PAD, FPGA_LED1_PAD_CFG);
	eos_s3_io_mux(FPGA_LED2_PAD, FPGA_LED2_PAD_CFG);

	eos_s3_fbio_select(FPGA_LED0_PAD, FPGA_LED0_FBIO_SEL);
	eos_s3_fbio_select(FPGA_LED1_PAD, FPGA_LED1_FBIO_SEL);
	eos_s3_fbio_select(FPGA_LED2_PAD, FPGA_LED2_FBIO_SEL);

}

void program_fpga_ip(void)
{
	/* Load bitstrem into FPGA */
	load_fpga(sizeof(axFPGABitStream), axFPGABitStream);

	/* Configure IOs */
	config_ios();
}


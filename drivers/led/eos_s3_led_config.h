/*
 * ==========================================================
 *
 *    Copyright (C) 2020 QuickLogic Corporation             
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *
 *    File      : eos_s3_led_config.h
 *    Purpose   : This file contains the IO mux definitions for LEDs
 *    		                                                            
 *                                                          
 * ===========================================================
 *
 */


#ifndef _INC_EOS_S3_LED_CONFIG
#define _INC_EOS_S3_LED_CONFIG

#include <soc_pinmap.h>

/* Set FPGA_LED0 to PAD18 */
#define FPGA_LED0_PAD18 (PAD_CTRL_SEL_FPGA | PAD_OEN_NORMAL \
	| PAD_P_Z | PAD_SR_SLOW | PAD_E_4MA \
	| PAD_REN_DISABLE | PAD_SMT_DISABLE)
#define FPGA_LED0_PAD18_FBIO PAD18_FUNC_SEL_FBIO_18

/* Set FPGA_LED1 to PAD21 */
#define FPGA_LED1_PAD21 (PAD_CTRL_SEL_FPGA | PAD_OEN_NORMAL \
	| PAD_P_Z | PAD_SR_SLOW | PAD_E_4MA \
	| PAD_REN_DISABLE | PAD_SMT_DISABLE)
#define FPGA_LED1_PAD21_FBIO PAD21_FUNC_SEL_FBIO_21

/* Set FPGA_LED2 to PAD22 */
#define FPGA_LED2_PAD22 (PAD_CTRL_SEL_FPGA | PAD_OEN_NORMAL \
	| PAD_P_Z | PAD_SR_SLOW | PAD_E_4MA \
	| PAD_REN_DISABLE | PAD_SMT_DISABLE)
#define FPGA_LED2_PAD22_FBIO PAD22_FUNC_SEL_FBIO_22

#define FPGA_LED0_PAD		18
#define FPGA_LED0_PAD_CFG	FPGA_LED0_PAD18
#define FPGA_LED0_FBIO_SEL	FPGA_LED0_PAD18_FBIO
#define FPGA_LED1_PAD		21
#define FPGA_LED1_PAD_CFG	FPGA_LED1_PAD21
#define FPGA_LED1_FBIO_SEL	FPGA_LED1_PAD21_FBIO
#define FPGA_LED2_PAD		22
#define FPGA_LED2_PAD_CFG	FPGA_LED2_PAD22
#define FPGA_LED2_FBIO_SEL	FPGA_LED2_PAD22_FBIO


#endif /* _INC_EOS_S3_LED_CONFIG */

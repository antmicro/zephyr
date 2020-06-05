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
 *    File      : pwm_eos_s3.c
 *    Purpose   : This file has the function to load pwm fpga ip
 *    		                                                            
 *                                                          
 * ===========================================================
 *
 */

#include <zephyr.h>
#include <soc.h>
#include <fpga_loader.h>
#include "eos_s3_pwm_ip.h"

void program_fpga_ip()
{
	// Load bitstrem into FPGA
	load_fpga(sizeof(axFPGABitStream),axFPGABitStream);
}


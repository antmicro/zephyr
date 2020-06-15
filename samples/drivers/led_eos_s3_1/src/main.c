/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <device.h>
#include <soc.h>

void main(void)
{
    	printk("\n\n");
    	printk( "##########################\n");
    	printk( "Quicklogic Open Platform 2.0\n");
    	printk( "SW Version: ");
    	printk("OP2-QuickFeather-led-eos-s3-sample1");
    	printk( "\n" );
    	printk( __DATE__ " " __TIME__ "\n" );
    	printk( "##########################\n\n");

	while (1);
}

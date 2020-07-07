/*
 * Copyright (c) 2020 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <init.h>
#include <soc.h>
#include <board.h>

static int eos_s3_board_init(struct device *arg)
{
	ARG_UNUSED(arg);

	/* IO MUX setup for UART */
	eos_s3_io_mux(UART_TX_PAD, UART_TX_PAD_CFG);
	eos_s3_io_mux(UART_RX_PAD, UART_RX_PAD_CFG);

	IO_MUX->UART_rxd_SEL = UART_RX_SEL;

#ifdef CONFIG_SPI_EOS_S3
	eos_s3_io_mux(SPI_CLK_PAD, SPI_CLK_PAD_CFG);
	eos_s3_io_mux(SPI_MISO_PAD, SPI_MISO_PAD_CFG);
	eos_s3_io_mux(SPI_MOSI_PAD, SPI_MOSI_PAD_CFG);
	eos_s3_io_mux(SPI_SS1_PAD, SPI_SS1_PAD_CFG);
#endif

#if defined CONFIG_PWM_LITEX || CONFIG_EOS_S3_PWM
	eos_s3_io_mux(PWM0_PAD, PWM0_PAD_CFG);
	eos_s3_io_mux(PWM1_PAD, PWM1_PAD_CFG);
	eos_s3_io_mux(PWM2_PAD, PWM2_PAD_CFG);
#endif

#ifdef CONFIG_UART_LITEUART
	eos_s3_io_mux(FB_UART_TX_PAD, FB_UART_TX_PAD_CFG);
	eos_s3_io_mux(FB_UART_RX_PAD, FB_UART_RX_PAD_CFG);
#endif

	return 0;
}

SYS_INIT(eos_s3_board_init, PRE_KERNEL_1, CONFIG_BOARD_INIT_PRIORITY);

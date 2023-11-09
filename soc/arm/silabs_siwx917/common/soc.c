/*
 * Copyright (c) 2023 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include "rsi_rom_clks.h"

int silabs_siwx917_init(void)
{
	SystemInit();
	SystemCoreClockUpdate();

#if DT_NODE_HAS_STATUS(DT_NODELABEL(uart0), okay)
	RSI_CLK_UsartClkConfig(M4CLK, ENABLE_STATIC_CLK, 0, USART1, 0, 1);
#endif

	return 0;
}

SYS_INIT(silabs_siwx917_init, PRE_KERNEL_1, 0);

/* TODO: comment explaining what we're doing here */
extern void *__co_stack_top;
Z_ISR_DECLARE(30, ISR_FLAG_DIRECT, __co_stack_top, 0);

/*
 * Problem: SiWx917's bootloader requires IRQn 32 to hold payload's entry point address
 * Solution: declare a direct interrupt
 */
extern void z_arm_reset(void);
Z_ISR_DECLARE(32, ISR_FLAG_DIRECT, z_arm_reset, 0);

#ifdef CONFIG_WIFI_SIWG917
/* TODO: comment explaining what we're doing here */
extern void IRQ074_Handler(void);
Z_ISR_DECLARE(74, ISR_FLAG_DIRECT, IRQ074_Handler, 0);
#endif

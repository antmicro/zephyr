/*
 * Copyright (c) 2023 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

MEMORY
{
	udma0 (rwx): ORIGIN = 0x2fc00, LENGTH = 0x400
	udma1 (rwx): ORIGIN = 0x24060000, LENGTH = 0x400
}

#include <zephyr/arch/arm/aarch32/cortex_m/scripts/linker.ld>

SECTIONS
{
	/* TODO: don't hardcode the size! */
	co_stack_size = 0x3000;
	.co_stack :
	{
		__co_stack_limit = .;
		KEEP(*(.co_stack*))
		. = ALIGN(4);
		. += co_stack_size;
		__co_stack_top = .;
	} > RAM

	.common_tcm_code :
	{
		*(.common_tcm_code*)
	} > FLASH

	.udma_addr0 :
	{
		*(.udma_addr0*)
	} > udma0 AT> FLASH

	.udma_addr1 :
	{
		*(.udma_addr1*)
	} > udma1 AT> FLASH

}

/*
 * Copyright (c) 2020 Antmicro <www.antmicro.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <kernel.h>
#include <init.h>
#include <soc.h>
#include <soc_pinmap.h>
#include <arch/arm/aarch32/cortex_m/cmsis.h>

/* EOS S3 has WIC (Wake-up Interrupt Controller) which is an independent
 * interrupt controller that also handles enabling, disabling and
 * clearing IRQs. To actually make IRQs work properly we need to
 * override NVIC functions and add there also WIC.
 * GPIO interrupts are handled separately by gpio_eos_s3.c driver.
 */
void EOSS3_DisableIRQ(IRQn_Type IRQn)
{
	if ((int32_t)(IRQn) >= 0) {
		NVIC->ICER[(((uint32_t)IRQn) >> 5UL)] =
			(uint32_t)(1UL << (((uint32_t)IRQn) & 0x1FUL));
		if ((int32_t)IRQn != WIC_GPIO_IRQ_BASE) {
			INTR_CTRL->OTHER_INTR_EN_M4 &=
				~(1 << (IRQn - WIC_OTHER_IRQ_BASE));
		}
		__DSB();
		__ISB();
	}
}

void EOSS3_EnableIRQ(IRQn_Type IRQn)
{
	if ((int32_t)(IRQn) >= 0) {
		__COMPILER_BARRIER();
		NVIC->ISER[(((uint32_t)IRQn) >> 5UL)] =
			(uint32_t)(1UL << (((uint32_t)IRQn) & 0x1FUL));
		__COMPILER_BARRIER();
		if ((int32_t)IRQn != WIC_GPIO_IRQ_BASE) {
			INTR_CTRL->OTHER_INTR_EN_M4 |=
				(1 << (IRQn - WIC_OTHER_IRQ_BASE));
		}
	}
}

void EOSS3_ClearPendingIRQ(IRQn_Type IRQn)
{
	if ((int32_t)(IRQn) >= 0) {
		NVIC->ICPR[(((uint32_t)IRQn) >> 5UL)] =
			(uint32_t)(1UL << (((uint32_t)IRQn) & 0x1FUL));
		if ((int32_t)IRQn != WIC_GPIO_IRQ_BASE) {
			INTR_CTRL->OTHER_INTR |=
				(1 << (IRQn - WIC_OTHER_IRQ_BASE));
		}
	}
}

void eos_s3_lock_enable(void)
{
	MISC_CTRL->LOCK_KEY_CTRL = MISC_LOCK_KEY;
}

void eos_s3_lock_disable(void)
{
	MISC_CTRL->LOCK_KEY_CTRL = 1;
}

int eos_s3_io_mux(u32_t pad_nr, u32_t pad_cfg)
{
	volatile u32_t *p = (u32_t *)IO_MUX_BASE;

	if (pad_nr > EOS_S3_MAX_PAD_NR) {
		return -EINVAL;
	}

	p += pad_nr;
	*p = pad_cfg;

	return 0;
}

int eos_s3_fbio_select(u32_t pad_nr, u32_t ucFunc)
{
	u32_t uiExtRegAddr;
	u32_t *pExtRegAddr;

	uiExtRegAddr = ucFunc >> EXT_REG_OFFSET_SHIFT;

	if(uiExtRegAddr == FBIO_SEL_2)
    	{
    		uiExtRegAddr = uiExtRegAddr | IO_MUX_BASE;
    		pExtRegAddr = (uint32_t *)uiExtRegAddr;
    		*pExtRegAddr |= 1 << (pad_nr - 32);
    	}
    	else
    	{
    		uiExtRegAddr |= IO_MUX_BASE;
    		pExtRegAddr = (uint32_t *)uiExtRegAddr;
    		*pExtRegAddr |= 1 << pad_nr;
    	}

	return 0;
}

static void eos_s3_cru_init(void)
{
	/* Set desired frequency */
	AIP->OSC_CTRL_0 |= AIP_OSC_CTRL_EN;
	AIP->OSC_CTRL_0 &= ~AIP_OSC_CTRL_FRE_SEL;
	OSC_SET_FREQ_INC(HSOSC_60MHZ);

	while (!OSC_CLK_LOCKED()) {
		;
	}

	/* Enable all clocks for every domain */
	CRU->CLK_DIVIDER_CLK_GATING = (CLK_DIVIDER_A_CG | CLK_DIVIDER_B_CG
		| CLK_DIVIDER_C_CG | CLK_DIVIDER_D_CG | CLK_DIVIDER_F_CG
		| CLK_DIVIDER_G_CG | CLK_DIVIDER_H_CG | CLK_DIVIDER_I_CG
		| CLK_DIVIDER_J_CG);

	/* Turn off divisor for A0 domain */
	CRU->CLK_CTRL_A_0 = 0;

	/* Turn off divisor for A1 domain */
	CRU->CLK_CTRL_A_1 = 0;

	/* Enable UART, WDT and TIMER peripherals */
	CRU->C11_CLK_GATE = C11_CLK_GATE_PATH_0_ON;

	/* Set divider for domain C11 to ~ 5.12MHz */
	CRU->CLK_CTRL_D_0 = (CLK_CTRL_CLK_DIVIDER_ENABLE |
		CLK_CTRL_CLK_DIVIDER_RATIO_12);
}

#ifdef CONFIG_SOC_EOS_S3_FPGA
static void eos_s3_fpga_init(void)
{
	PMU->FFE_FB_PF_SW_WU = PMU_FFE_FB_PF_SW_WU_PF_WU
		| PMU_FFE_FB_PF_SW_WU_FB_WU
		| PMU_FFE_FB_PF_SW_WU_FFE_WU;
	CRU->FB_SW_RESET = FB_C21_DOMAIN_SW_RESET | FB_C16_DOMAIN_SW_RESET
		| FB_C09_DOMAIN_SW_RESET | FB_C02_DOMAIN_SW_RESET;

	CRU->C02_CLK_GATE = C02_CLK_GATE_PATH_0_ON | C02_CLK_GATE_PATH_1_ON
		| C02_CLK_GATE_PATH_2_ON;

	CRU->C08_X1_CLK_GATE = C08_X1_CLK_GATE_PATH_1_ON
		| C08_X1_CLK_GATE_PATH_2_ON;

	CRU->C16_CLK_GATE = C16_CLK_GATE_PATH_0_ON;

	CRU->C21_CLK_GATE = C21_CLK_GATE_PATH_0_ON;

	CRU->C09_CLK_GATE = C09_CLK_GATE_PATH_0_ON;

	PMU->GEN_PURPOSE_0 = 0;
	PMU->FB_ISOLATION = 0;
	CRU->FB_SW_RESET = 0;
	CRU->FB_MISC_SW_RST_CTL = 0;

	CRU->C01_CLK_GATE = C01_CLK_GATE_PATH_0_ON | C01_CLK_GATE_PATH_2_ON
		| C01_CLK_GATE_PATH_4_ON | C01_CLK_GATE_PATH_7_ON
		| C01_CLK_GATE_PATH_9_ON;

	CRU->C08_X4_CLK_GATE = C08_X4_CLK_GATE_PATH_0_ON;


	/* Setup Wishbone clock of FPGA to be divided by 8.
	 * Maximum Wishbone clock frequency supported by FPGA is 10MHz.
	 */
	CRU->CLK_CTRL_F_0 = (CLK_CTRL_CLK_DIVIDER_ENABLE |
		CLK_CTRL_CLK_DIVIDER_RATIO_8);
	CRU->CLK_CTRL_I_0 = (CLK_CTRL_CLK_DIVIDER_ENABLE |
		CLK_CTRL_CLK_DIVIDER_RATIO_8);
	CRU->CLK_CTRL_B_0 = (CLK_CTRL_CLK_DIVIDER_ENABLE |
		CLK_CTRL_CLK_DIVIDER_RATIO_8);

	/* Enable all FBIOs (FPGA IOs) */
	IO_MUX->FBIO_SEL_1_REG = 0xFFFFFFFF;
}
#endif

static int eos_s3_init(struct device *arg)
{
	u32_t key;

	ARG_UNUSED(arg);

	/* Clocks setup */
	eos_s3_lock_enable();
	eos_s3_cru_init();
	eos_s3_lock_disable();

#ifdef CONFIG_EOS_S3_PROGRAM_FPGA
	program_fpga_ip();
#endif

#ifdef CONFIG_SOC_EOS_S3_FPGA
	eos_s3_fpga_init();
#endif

	SCnSCB->ACTLR |= SCnSCB_ACTLR_DISDEFWBUF_Msk;

	/* Clear all interrupts */
	INTR_CTRL->OTHER_INTR = 0xFFFFFF;

	key = irq_lock();

	NMI_INIT();

	irq_unlock(key);

	return 0;
}

SYS_INIT(eos_s3_init, PRE_KERNEL_1, 0);

/*
 * ==========================================================
 *
 *   Copyright 2020 QuickLogic
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 *
 *    File   : fpga_loader.c
 *    Purpose: Contains functionality to load FPGA
 *
 *=========================================================
 */


#include <zephyr.h>
#include <soc.h>

#define CFG_CTL_CFG_DATA                (*(volatile u32_t *)(0x40014FFC))
#define CFG_CTL_CFG_CTL                 (*(volatile u32_t *)(0x40014000))


int load_fpga(u32_t img_size, u32_t *image_ptr)
{
	unsigned int    i = 0;
	u32_t        chunk_cnt = 0;
	volatile u32_t   *gFPGAPtr = (volatile u32_t *)image_ptr;

	IO_MUX->PAD_19_CTRL = 0x00000180;

	enable_fpga_clocks();

	/* wait some time for fpga to get reset pulse */
#if 0
	k_sleep(100);
#else
	for (i = 0; i < 60; i++)
		PMU->GEN_PURPOSE_1  = i << 4;
#endif

	/* Configuration of CFG_CTRL for writes */
	CFG_CTL_CFG_CTL = 0xBDFF;

#if 0
	k_sleep(100);
#else
	for (i = 0; i < 60; i++)
		PMU->GEN_PURPOSE_1  = i << 4;
#endif

	for (chunk_cnt = 0; chunk_cnt < (img_size/4); chunk_cnt++)
		CFG_CTL_CFG_DATA = gFPGAPtr[chunk_cnt];

	/* wait some time for fpga to get reset pulse */
#if 0
	k_sleep(100);
#else
	for (i = 0; i < 60; i++)
		PMU->GEN_PURPOSE_1  = i << 4;
#endif

	/* exit config mode */
	CFG_CTL_CFG_CTL = 0x0;
	PMU->GEN_PURPOSE_0 = 0; /* set APB_FB_EN = 0 for normal mode */

	PMU->FB_ISOLATION = 0;

	CRU->FB_SW_RESET = 0;
	CRU->FB_MISC_SW_RST_CTL = 0;
	PMU->GEN_PURPOSE_1 = 0x90;

	/* required wait time before releasing LTH_ENB */
#if 0
	k_sleep(100);
#else
	for (i = 0; i < 60; i++)
		PMU->GEN_PURPOSE_1  = i << 4;
#endif
	IO_MUX->PAD_19_CTRL = 0x000009a0;

	return 0;
}

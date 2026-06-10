#!/usr/bin/env bash

set -euxo pipefail

west build -p always -d build-antmicro -b stm32h747i_disco/stm32h747xx/m7 -- \
	-DFILE_SUFFIX=antmicro
sudo openocd -f ./config.cfg -f ./stm32h7x_dual_bank.cfg -c "adapter speed 100" \
	-c "init; program ./build-antmicro/zephyr/zephyr.elf verify reset exit"
sudo picocom /dev/ttyUSB2 -b 115200

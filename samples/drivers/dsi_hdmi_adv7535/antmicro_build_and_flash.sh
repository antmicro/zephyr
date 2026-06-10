#!/usr/bin/env bash

# NOTE: Assumptions when running this script:
# - You can talk with the board without sudo
# - Zephyr python venv is active

set -euxo pipefail

west build -p always -d build-antmicro -b stm32h747i_disco/stm32h747xx/m7 -- \
	-DFILE_SUFFIX=antmicro
openocd -f ./config.cfg -f ./stm32h7x_dual_bank.cfg -c "adapter speed 100" \
	-c "init; program ./build-antmicro/zephyr/zephyr.elf verify reset exit"
picocom /dev/ttyUSB2 -b 115200

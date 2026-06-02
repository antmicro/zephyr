#!/usr/bin/env bash

set -euxo pipefail

west build -b stm32h747i_disco/stm32h747xx/m7
sudo openocd -f ./config.cfg -f ./stm32h7x_dual_bank.cfg -c "adapter speed 100" -c "init; program ./build/zephyr/zephyr.elf verify reset exit"
sudo picocom /dev/ttyUSB2 -b 115200

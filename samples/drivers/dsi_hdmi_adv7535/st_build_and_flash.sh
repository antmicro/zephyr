#!/usr/bin/env bash

# NOTE: Assumptions when running this script:
# - Zephyr python venv is active

set -euxo pipefail

west build -p always -d build-st -b stm32h747i_disco/stm32h747xx/m7 -- -DFILE_SUFFIX=st
west flash -d build-st
picocom /dev/ttyACM0 -b 115200

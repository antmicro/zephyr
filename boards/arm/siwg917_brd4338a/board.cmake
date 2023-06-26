# Copyright (c) 2023 Antmicro <www.antmicro.com>
#
# SPDX-License-Identifier: Apache-2.0

board_runner_args(silabs_commander "--device=SiWG917M612LGTAA")
include(${ZEPHYR_BASE}/boards/common/silabs_commander.board.cmake)

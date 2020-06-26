# Copyright (C) 2020 QuickLogic Corporation
# Licensed under the Apache License, Version 2.0

cmake_minimum_required(VERSION 3.13.1)
include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(led_eos_s3_basic)

FILE(GLOB app_sources src/*.c)
target_sources(app PRIVATE ${app_sources})
#add_definitions( -DDBUG)

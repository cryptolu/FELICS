#!/bin/bash

#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2015-2019 University of Luxembourg
#
# Author: Luan Cardoso (2019), Virat Shejwalkar (2017),
#         Daniel Dinu (2015), and Yann Le Corre (2015)
#
# This file is part of FELICS.
#
# FELICS is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# FELICS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

#
# Constants
#


PC_CIPHER_FILE=./cipher.elf
PC_SCENARIO1_FILE=./scenario1.elf
PC_SCENARIO2_FILE=./scenario2.elf
PC_SCENARIO3_FILE=./scenario3.elf
PC_SCENARIO4_FILE=./scenario4.elf
PC_SCENARIO5_FILE=./scenario5.elf
PC_SCENARIO6_FILE=./scenario6.elf

PC_OUTPUT_FILE=pc_execution_time.log

AVR_EXECUTION_TIME_LOG_FILE=avr_execution_time.log

MSP_CIPHER_MSPDEBUG_EXECUTION_TIME_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_cipher_execution_time.cmd
MSP_CIPHER_MSPDEBUG_EXECUTION_TIME_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_cipher_execution_time_sections.cmd

MSP_SCENARIO1_MSPDEBUG_EXECUTION_TIME_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_scenario1_execution_time.cmd
MSP_SCENARIO1_MSPDEBUG_EXECUTION_TIME_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_scenario1_execution_time_sections.cmd

MSP_SCENARIO2_MSPDEBUG_EXECUTION_TIME_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_scenario2_execution_time.cmd
MSP_SCENARIO2_MSPDEBUG_EXECUTION_TIME_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_scenario2_execution_time_sections.cmd

MSP_SCENARIO3_MSPDEBUG_EXECUTION_TIME_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_scenario3_execution_time.cmd
MSP_SCENARIO3_MSPDEBUG_EXECUTION_TIME_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_scenario3_execution_time_sections.cmd

MSP_SCENARIO4_MSPDEBUG_EXECUTION_TIME_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_scenario4_execution_time.cmd
MSP_SCENARIO4_MSPDEBUG_EXECUTION_TIME_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_scenario4_execution_time_sections.cmd

MSP_SCENARIO5_MSPDEBUG_EXECUTION_TIME_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_scenario5_execution_time.cmd
MSP_SCENARIO5_MSPDEBUG_EXECUTION_TIME_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_scenario5_execution_time_sections.cmd

MSP_SCENARIO6_MSPDEBUG_EXECUTION_TIME_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_scenario6_execution_time.cmd
MSP_SCENARIO6_MSPDEBUG_EXECUTION_TIME_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/execution_time/msp_scenario6_execution_time_sections.cmd

MSPDEBUG_EXECUTION_TIME_LOG_FILE=mspdebug_execution_time.log
MSPDEBUG_EXECUTION_TIME_SECTIONS_LOG_FILE=mspdebug_execution_time_sections.log

MAKE_LOG_FILE=cipher_execution_time_make.log

ARM_SERIAL_TERMINAL=./../../../../../common/scripts/arm/arm_serial_terminal.py

ARM_SERIAL_TERMINAL_OUTPUT_FILE=serial.out

ARM_OPERATION_MAX_EXECUTION_TIME=4294967290

TABLE_HORIZONTAL_LINE_LENGTH=105

CIPHER_MAKEFILE=./../../../common/cipher.mk

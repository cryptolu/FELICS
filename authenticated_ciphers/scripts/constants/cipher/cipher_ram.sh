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


CONSTANTS_SOURCE_FILE=./../source/constants.h
CIPHER_HEADER_FILE=./../../../common/cipher.h

BLOCK_SIZE_DEFINE='#define BLOCK_SIZE'
KEY_SIZE_DEFINE='#define KEY_SIZE'
NONCE_SIZE_DEFINE='#define NONCE_SIZE'
STATE_SIZE_DEFINE='#define STATE_SIZE'
TAG_SIZE_DEFINE='#define TAG_SIZE'

MESSAGE_SIZE_DEFINE='#define MESSAGE_SIZE'
ASSOCIATED_DATA_SIZE_DEFINE='#define ASSOCIATED_DATA_SIZE'

TEST_MESSAGE_SIZE_DEFINE='#define TEST_MESSAGE_SIZE'
TEST_ASSOCIATED_DATA_SIZE_DEFINE='#define TEST_ASSOCIATED_DATA_SIZE'


MEMORY_PATTERN=(0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88 0x99 0xAA)

MEMORY_FILE=memory.mem
MEMORY_SIZE=2000

PC_CIPHER_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_cipher_stack.gdb
PC_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_cipher_stack_sections.gdb

PC_SCENARIO1_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario1_stack.gdb
PC_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario1_stack_sections.gdb

PC_SCENARIO2_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario2_stack.gdb
PC_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario2_stack_sections.gdb

PC_SCENARIO3_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario3_stack.gdb
PC_SCENARIO3_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario3_stack_sections.gdb

PC_SCENARIO4_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario4_stack.gdb
PC_SCENARIO4_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario4_stack_sections.gdb

PC_SCENARIO5_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario5_stack.gdb
PC_SCENARIO5_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario5_stack_sections.gdb

PC_SCENARIO6_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario6_stack.gdb
PC_SCENARIO6_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario6_stack_sections.gdb

AVR_CIPHER_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_cipher_stack.gdb
AVR_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_cipher_stack_sections.gdb

AVR_SCENARIO1_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario1_stack.gdb
AVR_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario1_stack_sections.gdb

AVR_SCENARIO2_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario2_stack.gdb
AVR_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario2_stack_sections.gdb

AVR_SCENARIO3_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario3_stack.gdb
AVR_SCENARIO3_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario3_stack_sections.gdb

AVR_SCENARIO4_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario4_stack.gdb
AVR_SCENARIO4_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario4_stack_sections.gdb

AVR_SCENARIO5_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario5_stack.gdb
AVR_SCENARIO5_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario5_stack_sections.gdb

AVR_SCENARIO6_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario6_stack.gdb
AVR_SCENARIO6_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario6_stack_sections.gdb

MSP_CIPHER_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_cipher_stack.gdb
MSP_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_cipher_stack_sections.gdb

MSP_SCENARIO1_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario1_stack.gdb
MSP_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario1_stack_sections.gdb

MSP_SCENARIO2_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario2_stack.gdb
MSP_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario2_stack_sections.gdb

MSP_SCENARIO3_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario3_stack.gdb
MSP_SCENARIO3_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario3_stack_sections.gdb

MSP_SCENARIO4_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario4_stack.gdb
MSP_SCENARIO4_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario4_stack_sections.gdb

MSP_SCENARIO5_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario5_stack.gdb
MSP_SCENARIO5_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario5_stack_sections.gdb

MSP_SCENARIO6_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario6_stack.gdb
MSP_SCENARIO6_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario6_stack_sections.gdb

ARM_CIPHER_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_cipher_stack.gdb
ARM_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_cipher_stack_sections.gdb

ARM_SCENARIO1_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario1_stack.gdb
ARM_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario1_stack_sections.gdb

ARM_SCENARIO2_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario2_stack.gdb
ARM_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario2_stack_sections.gdb

ARM_SCENARIO3_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario3_stack.gdb
ARM_SCENARIO3_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario3_stack_sections.gdb

ARM_SCENARIO4_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario4_stack.gdb
ARM_SCENARIO4_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario4_stack_sections.gdb

ARM_SCENARIO5_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario5_stack.gdb
ARM_SCENARIO5_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario5_stack_sections.gdb

ARM_SCENARIO6_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario6_stack.gdb
ARM_SCENARIO6_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario6_stack_sections.gdb

GDB_STACK_LOG_FILE=gdb_stack.log
GDB_STACK_SECTIONS_LOG_FILE=gdb_stack_sections.log

SIMAVR_STACK_LOG_FILE=simavr_stack.log
SIMAVR_STACK_SECTIONS_LOG_FILE=simavr_stack_sections.log

MSPDEBUG_STACK_LOG_FILE=mspdebug_stack.log
MSPDEBUG_STACK_SECTIONS_LOG_FILE=mspdebug_stack_sections.log

MAX_JLINK_GDB_SERVER_START_ATTEMPTS=100

JLINK_GDB_SERVER_STACK_LOG_FILE=jlink_gdb_server_stack.log
JLINK_GDB_SERVER_STACK_SECTIONS_LOG_FILE=jlink_gdb_server_stack_sections.log

ARM_TARGET_FILE=none

MAKE_LOG_FILE=cipher_ram_make.log

TABLE_HORIZONTAL_LINE_LENGTH=183

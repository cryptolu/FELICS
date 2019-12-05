#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2017 University of Luxembourg
#
# Written in 2017 by Virat Shejwalkar <virat.shejwalkar@uni.lu>
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

DIGEST_SIZE_DEFINE="#define DIGEST_SIZE"
BLOCK_SIZE_DEFINE='#define BLOCK_SIZE'
STATE_SIZE_DEFINE='#define STATE_SIZE'

MESSAGE_SIZE_DEFINE='#define MESSAGE_SIZE'

TEST_MESSAGE_SIZE_DEFINE='#define TEST_MESSAGE_SIZE'

SPONGE_DEFINE="#define SPONGE"

MEMORY_PATTERN=(0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88 0x99 0xAA)

MEMORY_FILE=memory.mem
MEMORY_SIZE=2000

# PC
PC_CIPHER_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_cipher_stack.gdb
PC_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_cipher_stack_sections.gdb

PC_SCENARIO1A_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario1a_stack.gdb
PC_SCENARIO1A_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario1a_stack_sections.gdb

PC_SCENARIO1B_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario1b_stack.gdb
PC_SCENARIO1B_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario1b_stack_sections.gdb

PC_SCENARIO1C_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario1c_stack.gdb
PC_SCENARIO1C_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario1c_stack_sections.gdb

PC_SCENARIO2_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario2_stack.gdb
PC_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/pc_scenario2_stack_sections.gdb

# AVR
AVR_CIPHER_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_cipher_stack.gdb
AVR_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_cipher_stack_sections.gdb

AVR_SCENARIO1A_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario1a_stack.gdb
AVR_SCENARIO1A_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario1a_stack_sections.gdb

AVR_SCENARIO1B_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario1b_stack.gdb
AVR_SCENARIO1B_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario1b_stack_sections.gdb

AVR_SCENARIO1C_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario1c_stack.gdb
AVR_SCENARIO1C_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario1c_stack_sections.gdb

AVR_SCENARIO2_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario2_stack.gdb
AVR_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/avr_scenario2_stack_sections.gdb

# MSP
MSP_CIPHER_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_cipher_stack.gdb
MSP_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_cipher_stack_sections.gdb

MSP_SCENARIO1A_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario1a_stack.gdb
MSP_SCENARIO1A_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario1a_stack_sections.gdb

MSP_SCENARIO1B_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario1b_stack.gdb
MSP_SCENARIO1B_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario1b_stack_sections.gdb

MSP_SCENARIO1C_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario1c_stack.gdb
MSP_SCENARIO1C_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario1c_stack_sections.gdb

MSP_SCENARIO2_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario2_stack.gdb
MSP_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/msp_scenario2_stack_sections.gdb

# ARM
ARM_CIPHER_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_cipher_stack.gdb
ARM_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_cipher_stack_sections.gdb

ARM_SCENARIO1A_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario1a_stack.gdb
ARM_SCENARIO1A_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario1a_stack_sections.gdb

ARM_SCENARIO1B_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario1b_stack.gdb
ARM_SCENARIO1B_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario1b_stack_sections.gdb

ARM_SCENARIO1C_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario1c_stack.gdb
ARM_SCENARIO1C_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario1c_stack_sections.gdb

ARM_SCENARIO2_GDB_STACK_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario2_stack.gdb
ARM_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE=./../../../../scripts/cipher/stack/arm_scenario2_stack_sections.gdb

GDB_STACK_LOG_FILE=gdb_stack.log
GDB_STACK_SECTIONS_LOG_FILE=gdb_stack_sections.log

SIMAVR_STACK_LOG_FILE=simavr_stack.log
SIMAVR_STACK_SECTIONS_LOG_FILE=simavr_stack_sections.log

MSPDEBUG_STACK_LOG_FILE=mspdebug_stack.log
MSPDEBUG_STACK_SECTIONS_LOG_FILE=mspdebug_stack_sections.log

JLINK_GDB_SERVER_STACK_LOG_FILE=jlink_gdb_server_stack.log
JLINK_GDB_SERVER_STACK_SECTIONS_LOG_FILE=jlink_gdb_server_stack_sections.log

UPLOAD_CIPHER=upload-cipher
UPLOAD_SCENARIO1A=upload-scenario1a
UPLOAD_SCENARIO1B=upload-scenario1b
UPLOAD_SCENARIO1C=upload-scenario1c
UPLOAD_SCENARIO2=upload-scenario2

MAKE_LOG_FILE=cipher_ram_make.log

TABLE_HORIZONTAL_LINE_LENGTH=106
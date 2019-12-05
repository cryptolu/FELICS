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


# Display help information
function display_help()
{
    echo ""
    echo "Call this script to check if the cipher implementation is compliant with the framework"
    echo "    ./check_cipher.sh [{-h|--help}] [--version] [{-m|--mode}=[0|1]] [{-s|--scenario}=[0|1|2|3|4|5|6]] [{-a|--architecture}=[PC|AVR|MSP|ARM]] [{-t|--target}=[...]] [{-o|--output}=[...]] [{-co|--compiler_options}='...']"
    echo ""
    echo "    To call from a cipher build folder use:"
    echo "        ./../../../../scripts/cipher/check_cipher.sh [options]"
    echo ""
    echo "    Options:"
    echo "        -h, --help"
    echo "            Display help information"
    echo "        --version"
    echo "            Display version information"
    echo "        -m, --mode"
    echo "            Specifies which output mode to use"
    echo "                0 - raw table for given cipher"
    echo "                1 - raw data for given cipher"
    echo "                Default: 0"
    echo "        -s, --scenario"
    echo "            Specifies which scenario is used"
    echo "                0 - cipher scenario"
    echo "                1 - scenario 1"
    echo "                2 - scenario 2"
    echo "                3 - scenario 3"
    echo "                4 - scenario 4"
    echo "                5 - scenario 5"
    echo "                6 - scenario 6"
    echo "                Default: 0"
    echo "        -a, --architecture"
    echo "            Specifies which architecture is used"
    echo "                PC - binary files are build for PC"
    echo "                AVR - binary files are build for AVR device"
    echo "                MSP - binary file are build for MSP device"
    echo "                ARM - binary files are build for ARM device"
    echo "                Default: PC"
    echo "        -t, --target"
    echo "            Specifies which is the target path. The relative path is computed from the directory where script was called"
    echo "                Default: ."
    echo "        -o, --output"
    echo "            Specifies where to output the results. The relative path is computed from the directory where script was called"
    echo "                Default: /dev/tty"
    echo "        -co,--compiler_options"
    echo "            Specifies the compiler options"
    echo "                List of values: '-O3 --param max-unroll-times=5 --param max-unrolled-insns=100 ...'"
    echo "                Default: -O3"
    echo ""
    echo "    Examples:"
    echo "        ./../../../../scripts/cipher/check_cipher.sh -m=0"
    echo "        ./../../../../scripts/cipher/check_cipher.sh --mode=1 --architecture=MSP"
    echo "        ./../../../../scripts/cipher/check_cipher.sh -o=results.txt"
    echo "        ./check_cipher.sh -t=./../../source/ciphers/CipherName_BlockSizeInBits_KeySizeInBits_NonceSizeInBits_StateSizeInBits_TagSizeInBits_v01/build"
    echo ""

    exit
}

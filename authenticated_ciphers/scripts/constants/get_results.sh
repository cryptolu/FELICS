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


SCRIPT_RESULTS_DIR_PATH=./../results/AuthenticatedCiphers/
SCRIPT_OLD_RESULTS_DIR_PATH=./../results/old_AuthenticatedCiphers/
SCRIPT_NEW_RESULTS_DIR_PATH=./../results/new_AuthenticatedCiphers/

RESULTS_DIR_NAME=AuthenticatedCiphers

RESULTS_INFO_DIR_NAME=Info

RESULTS_FILE_NAME=AuthenticatedCiphers

ZIP_FILE_EXTENSION=.zip

TIMESTAMP_FILE_PATH=./../results/AuthenticatedCiphers/TIMESTAMP

DEFAULT_FILE_PREFIX=FELICS

CSV_RESULTS_HEADER_LENGTH=3

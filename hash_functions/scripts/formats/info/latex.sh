#!/bin/bash

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
# Functions to generate LaTeX data table
#


# Add LaTeX table header
# Parameters:
# 	$1 - the output file
function add_latex_table_header()
{
	local output_file=$1
	

	# Clear output
	echo -n "" > $output_file
}


# Add LaTeX table row
# Parameters:
# 	$1 - the output file
# 	$2 - the hash name
# 	$3 - the hash block size
# 	$4 - the hash state size
#   $5 - the hash digest size
# 	$6 - the hash implementation version
# 	$7 - the hash implementation info
# 	$8 - the hash implementation authors
function add_latex_table_row()
{
	local output_file=$1
	local hash_name=$2
	local hash_block_size=$3
	local hash_state_size=$4
	local hash_digest_size=$5
	local hash_implementation_version=$6
	local hash_implementation_info=$7
	local hash_implementation_authors=$8


	printf "%s" "$hash_name" >> $output_file
	printf " " >> $output_file
	printf "%s" "$hash_block_size" >> $output_file
	printf " " >> $output_file
	printf "%s" "$hash_state_size" >> $output_file
	printf " " >> $output_file
	printf "%s" "$hash_digest_size" >> $output_file
	printf " " >> $output_file
	printf "%s" "$hash_implementation_version" >> $output_file
	printf " " >> $output_file
	printf "%s" "$hash_implementation_info" >> $output_file
	printf " " >> $output_file
	printf "%s" "$hash_implementation_authors" >> $output_file
	printf " " >> $output_file
	printf "\n" >> $output_file
}


# Add LaTeX table footer
# Parameters:
# 	$1 - the output file
function add_latex_table_footer()
{
	local output_file=$1
}

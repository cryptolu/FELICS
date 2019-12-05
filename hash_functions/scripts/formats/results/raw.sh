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
# Constants
#

SCENARIO_0_TABLE_HORIZONTAL_LINE_LENGTH=438


#
# Functions to generate raw data table
#


# Add raw table header
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
# 	$3 - the architecture
function add_raw_table_header()
{
	local output_file=$1
	local scenario=$2
	local architecture=$3
	

	# Clear output
	echo -n "" > $output_file

	# Table title
	title_position=$(($SCENARIO_0_TABLE_HORIZONTAL_LINE_LENGTH / 2 + 15))		
	printf " %"$title_position"s " "Architecture: $architecture; Scenario: $scenario" >> $output_file
	printf "\n" >> $output_file

	printf "%0.s-" $(seq 1 $SCENARIO_0_TABLE_HORIZONTAL_LINE_LENGTH) >> $output_file
	printf "\n" >> $output_file
	printf "| %92s | %54s | %73s | %149s | %54s |\n" "Hash Info" "Implementation Info" "Code Size" "RAM" "Execution Time" >> $output_file
	printf "%0.s-" $(seq 1 $SCENARIO_0_TABLE_HORIZONTAL_LINE_LENGTH) >> $output_file
	printf "\n" >> $output_file
	printf "| %16s | %16s | %16s | %16s | %16s | %16s | %16s | %16s | %16s | %16s | %16s | %16s | %16s | %16s | %16s | %16s | %16s | %16s | %16s | %16s | %16s | %16s | %16s |\n" "Hash" "Digest Size" "State Size" "Block Size" "Version" "Language" "Options" "Initialize" "Compress" "Finalize" "Total" "Initialize Stack" "Compress Stack" "Finalize Stack" "Initialize Data" "Compress Data" "Finalize Data" "Common Data" "Total Data" "Initialize" "Compress" "Finalize" >> $output_file
	printf "%0.s-" $(seq 1 $SCENARIO_0_TABLE_HORIZONTAL_LINE_LENGTH) >> $output_file
			
	printf "\n" >> $output_file
}


# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
# 	$3 - the hash name
#	$4 - the hash block size
#	$5 - the hash state size
#	$6 - the hash digest size
#	$7 - the hash implementation version
#	$8 - the hash implementation language
#	$9 - the hash implementation compiler options
#	$10 - hash metrics values
function add_raw_table_row()
{
	local output_file=$1
	local scenario=$2
	local hash_name=$3
	local hash_block_size=$4
	local hash_state_size=$5
	local hash_digest_size=$6
	local hash_implementation_version=$7
	local hash_implementation_language=$8
	local hash_implementation_compiler_options=$9
	local hash_metrics_values=( ${@:10} )
	
	
	local column_length=16

	# Table line
	printf "| %"$column_length"s " "$hash_name" >> $output_file
	printf "| %"$column_length"s " "$hash_block_size" >> $output_file
	printf "| %"$column_length"s " "$hash_state_size" >> $output_file
	printf "| %"$column_length"s " "$hash_digest_size" >> $output_file
	printf "| %"$column_length"s " "$hash_implementation_version" >> $output_file
	printf "| %"$column_length"s " "$hash_implementation_language" >> $output_file
	printf "| %"$column_length"s " "$hash_implementation_compiler_options" >> $output_file

	for value in ${hash_metrics_values[@]}
	do
		printf "| %"$column_length"s " $value >> $output_file
	done
	printf "|\n" >> $output_file
}


# Add raw table footer
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
function add_raw_table_footer()
{
	local output_file=$1
	local scenario=$2

	local horizontal_line_length=$SCENARIO_0_TABLE_HORIZONTAL_LINE_LENGTH

	# Table footer
	printf "%0.s-" $(seq 1 $horizontal_line_length) >> $output_file
	printf "\n" >> $output_file
}

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
# 	$2 - the scenario
# 	$3 - the architecture
function add_latex_table_header()
{
	local output_file=$1
	local scenario=$2
	local architecture=$3
	

	# Clear output
	echo -n "" > $output_file

	case $scenario in
		$SCRIPT_SCENARIO_0)
			;;
		$SCRIPT_SCENARIO_1)
			;;
		$SCRIPT_SCENARIO_2)
			;;
		$SCRIPT_SCENARIO_3)
			;;
		$SCRIPT_SCENARIO_4)
			;;
	esac
}


# Add LaTeX table row
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
function add_latex_table_row()
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
	printf "%s" "$hash_implementation_language" >> $output_file
	printf " " >> $output_file
	printf "%s" "$hash_implementation_compiler_options" >> $output_file
	printf " " >> $output_file
	printf "\n" >> $output_file


	for value in ${hash_metrics_values[@]}
	do
		printf "%s" $value >> $output_file
		printf "\n" >> $output_file
	done
}


# Add LaTeX table footer
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
function add_latex_table_footer()
{
	local output_file=$1
	local scenario=$2

	case $scenario in
		$SCRIPT_SCENARIO_0)
			;;
		$SCRIPT_SCENARIO_1)
			;;
		$SCRIPT_SCENARIO_2)
			;;
		$SCRIPT_SCENARIO_3)
			;;
		$SCRIPT_SCENARIO_4)
			;;
	esac
}

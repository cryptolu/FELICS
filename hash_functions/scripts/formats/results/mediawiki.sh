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
# Functions to generate MediaWiki data table
#


# Add MediaWiki table header
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
# 	$3 - the architecture
function add_mediawiki_table_header()
{	
	local output_file=$1
	local scenario=$2
	local architecture=$3


	# Clear output
	echo -n "" > $output_file

	# Table title & header
	printf "{| class=\"wikitable sortable\" style=\"margin: auto;\"" >> $output_file
	printf "\n" >> $output_file
	printf "|+ Architecture: $architecture; Scenario: $scenario" >> $output_file
	printf "\n" >> $output_file
	printf "|-" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" colspan=\"5\" rowspan=\"2\" | Hash Info" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" colspan=\"3\" rowspan=\"2\" | Implementation Info" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" colspan=\"4\" rowspan=\"2\" | Code Size" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" colspan=\"8\" | RAM" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" colspan=\"3\" rowspan=\"2\" | Execution Time" >> $output_file
	printf "\n" >> $output_file
	printf "|-" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" colspan=\"3\" | Stack" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" colspan=\"5\" | Data" >> $output_file
	printf "\n" >> $output_file
	printf "|-" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Hash" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Block Size (bits)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | State Size (bits)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Digest Size (bits)" >> $output_file
	printf "\n" >> $output_file

	printf "! scope=\"col\" | Version" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Language" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Options" >> $output_file
	printf "\n" >> $output_file
	
	printf "! scope=\"col\" | Initialize (bytes)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Compress (bytes)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Finalize (bytes)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Total (bytes)" >> $output_file
	printf "\n" >> $output_file

	printf "! scope=\"col\" | Initialize (bytes)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Compress (bytes)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Finalize (bytes)" >> $output_file
	printf "\n" >> $output_file

	printf "! scope=\"col\" | Initialize (bytes)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Compress (bytes)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Finalize (bytes)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Common (bytes)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Total (bytes)" >> $output_file
	printf "\n" >> $output_file
	
	printf "! scope=\"col\" | Initialize (cycles)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Compress (cycles)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Finalize (cycles)" >> $output_file
	printf "\n" >> $output_file
}


# Add MediaWiki table row
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
function add_mediawiki_table_row()
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

	printf "|-" >> $output_file
	printf "\n" >> $output_file
	printf "! $hash_name" >> $output_file
	printf "\n" >> $output_file
	printf "| $hash_block_size" >> $output_file
	printf "\n" >> $output_file
	printf "| $hash_state_size" >> $output_file
	printf "\n" >> $output_file
	printf "| $hash_digest_size" >> $output_file
	printf "\n" >> $output_file
	printf "| $hash_implementation_version" >> $output_file
	printf "\n" >> $output_file
	printf "| $hash_implementation_language" >> $output_file
	printf "\n" >> $output_file
	printf "| $hash_implementation_compiler_options" >> $output_file
	printf "\n" >> $output_file


	for value in ${hash_metrics_values[@]}
	do
		printf "| %s" $value >> $output_file
		printf "\n" >> $output_file
	done
}


# Add MediaWiki table footer
# Parameters:
# 	$1 - the output file
# 	$2 - the scenario
function add_mediawiki_table_footer()
{
	local output_file=$1
	local scenario=$2

	
	printf "|}" >> $output_file
}

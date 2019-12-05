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
function add_mediawiki_table_header()
{	
	local output_file=$1


	# Clear output
	echo -n "" > $output_file


	# Table title & header
	printf "{| class=\"wikitable sortable\" style=\"margin: auto;\"" >> $output_file
	printf "\n" >> $output_file
	printf "|+ Hash Functions Implementation Info" >> $output_file
	printf "\n" >> $output_file
	printf "|-" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Hash" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Digest Size (bits)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | State Size (bits)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Block Size (bits)" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Implementation Version" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Implementation Info" >> $output_file
	printf "\n" >> $output_file
	printf "! scope=\"col\" | Implementation Authors" >> $output_file
	printf "\n" >> $output_file
}


# Add MediaWiki table row
# Parameters:
# 	$1 - the output file
# 	$2 - the hash name
# 	$3 - the hash block size
# 	$4 - the hash state size
#   $5 - the hash digest size
# 	$6 - the hash implementation version
# 	$7 - the hash implementation info
# 	$8 - the hash implementation authors
function add_mediawiki_table_row()
{
	local output_file=$1
	local hash_name=$2
	local hash_block_size=$3
	local hash_state_size=$4
	local hash_digest_size=$5
	local hash_implementation_version=$6
	local hash_implementation_info=$7
	local hash_implementation_authors=$8


	printf "|-" >> $output_file
	printf "\n" >> $output_file
	printf "! $hash_name" >> $output_file
	printf "\n" >> $output_file
	printf "! $hash_block_size" >> $output_file
	printf "\n" >> $output_file
	printf "! $hash_state_size" >> $output_file
	printf "\n" >> $output_file
	printf "! $hash_digest_size" >> $output_file
	printf "\n" >> $output_file
	printf "! $hash_implementation_version" >> $output_file
	printf "\n" >> $output_file
	printf "| $hash_implementation_info" >> $output_file
	printf "\n" >> $output_file
	printf "| $hash_implementation_authors" >> $output_file
	printf "\n" >> $output_file
}


# Add MediaWiki table footer
# Parameters:
# 	$1 - the output file
function add_mediawiki_table_footer()
{
	local output_file=$1

	
	printf "|}" >> $output_file
}

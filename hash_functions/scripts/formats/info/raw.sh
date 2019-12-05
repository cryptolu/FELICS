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
# Functions to generate raw data table
#


# Add raw table header
# Parameters:
# 	$1 - the output file
function add_raw_table_header()
{
	local output_file=$1
	

	# Clear output
	echo -n "" > $output_file


	# Table title
	title_position=$(($TABLE_HORIZONTAL_LINE_LENGTH / 2 + 15))		
	printf " %"$title_position"s " "Hash Functions Implementation Info" >> $output_file
	printf "\n" >> $output_file

	# Table header
	printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $output_file
	printf "\n" >> $output_file
	printf "| %"$TABLE_HASH_COLUMN_LENGTH"s | %"$TABLE_INFO_COLUMN_LENGTH"s | %"$TABLE_AUTHORS_COLUMN_LENGTH"s |\n" "Hash" "Implementation Info" "Implementation Authors" >> $output_file
	printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $output_file
	printf "\n" >> $output_file
}


# Add raw table row
# Parameters:
# 	$1 - the output file
# 	$2 - the hash name
# 	$3 - the hash block size
# 	$4 - the hash state size
#   $5 - the hash digest size
# 	$6 - the hash implementation version
# 	$7 - the hash implementation info
# 	$8 - the hash implementation authors
function add_raw_table_row()
{
	local output_file=$1
	local hash_name=$2
	local hash_block_size=$3
	local hash_state_size=$4
	local hash_digest_size=$5
	local hash_implementation_version=$6
	local hash_implementation_info=$7
	local hash_implementation_authors=$8


	local info_words=( $(echo ${hash_implementation_info} | tr " " "\n") )
	local info_line=""

	local authors_words=( $(echo ${hash_implementation_authors} | tr " " "\n") )
	local authors_line=""


	hash_name="$hash_name-$hash_block_size;$hash_state_size;$hash_digest_size v$hash_implementation_version"
	
	
	k=0
	i=0
	j=0
	info_line_ready=0
	authors_line_ready=0

	
	while [ "${info_words[i]}" != "" ] && [ "${authors_words[j]}" != "" ]
	do
		info_word=${info_words[i]}
		authors_word=${authors_words[j]}

		info_line_length=$((${#info_line} + ${#info_word}))
		authors_line_length=$((${#authors_line} + ${#authors_word}))
		
		if [ $info_line_length -lt $TABLE_INFO_COLUMN_LENGTH ] ; then
			info_line="$info_line $info_word"
			i=$(($i + 1))
		else
			info_line_ready=1
		fi

		if [ $authors_line_length -lt $TABLE_AUTHORS_COLUMN_LENGTH ] ; then
			authors_line="$authors_line $authors_word"
			j=$(($j + 1))
		else
			authors_line_ready=1
		fi

		if [ 1 -eq $info_line_ready ] && [ 1 -eq $authors_line_ready ] ; then
			if [ 0 -eq $k ] ; then
				printf "| %"$TABLE_HASH_COLUMN_LENGTH"s | %"$TABLE_INFO_COLUMN_LENGTH"s | %"$TABLE_AUTHORS_COLUMN_LENGTH"s |" "$hash_name" "$info_line" "$authors_line"  >> $output_file
			else
				printf "\n" >> $output_file
				printf "| %"$TABLE_HASH_COLUMN_LENGTH"s | %"$TABLE_INFO_COLUMN_LENGTH"s | %"$TABLE_AUTHORS_COLUMN_LENGTH"s |" "" "$info_line" "$authors_line"  >> $output_file
			fi

			info_line=""
			authors_line=""			

			k=$(($k + 1))

			info_line_ready=0
			authors_line_ready=0
		fi
	done


	# Implementation info
	while [ "${info_words[i]}" != "" ]
	do
		info_word=${info_words[i]}
		info_line_length=$((${#info_line} + ${#info_word}))

		if [ $info_line_length -lt $TABLE_INFO_COLUMN_LENGTH ] ; then
			info_line="$info_line $info_word"
		else
			if [ 0 -eq $k ] ; then
				printf "| %"$TABLE_HASH_COLUMN_LENGTH"s | %"$TABLE_INFO_COLUMN_LENGTH"s | %"$TABLE_AUTHORS_COLUMN_LENGTH"s |" "$hash_name" "$info_line" "$authors_line"  >> $output_file
			else
				printf "\n" >> $output_file
				printf "| %"$TABLE_HASH_COLUMN_LENGTH"s | %"$TABLE_INFO_COLUMN_LENGTH"s | %"$TABLE_AUTHORS_COLUMN_LENGTH"s |" "" "$info_line" "$authors_line" >> $output_file
			fi

			info_line="... $info_word"
			authors_line=""

			k=$(($k + 1))
		fi

		i=$(($i + 1))
	done

	
	# Authors info
	while [ "${authors_words[j]}" != "" ]
	do
		authors_word=${authors_words[j]}
		authors_line_length=$((${#authors_line} + ${#authors_word}))

		if [ $authors_line_length -lt $TABLE_AUTHORS_COLUMN_LENGTH ] ; then
			authors_line="$authors_line $authors_word"
		else
			if [ 0 -eq $k ] ; then
				printf "| %"$TABLE_HASH_COLUMN_LENGTH"s | %"$TABLE_INFO_COLUMN_LENGTH"s | %"$TABLE_AUTHORS_COLUMN_LENGTH"s |" "$hash_name" "$info_line" "$authors_line"  >> $output_file
			else
				printf "\n" >> $output_file
				printf "| %"$TABLE_HASH_COLUMN_LENGTH"s | %"$TABLE_INFO_COLUMN_LENGTH"s | %"$TABLE_AUTHORS_COLUMN_LENGTH"s |" "" "$info_line" "$authors_line" >> $output_file
			fi

			info_line=""
			authors_line="... $authors_word"

			k=$(($k + 1))
		fi

		j=$(($j + 1))
	done

	
	# Left part
	if [ 0 -eq $k ] ; then
		printf "| %"$TABLE_HASH_COLUMN_LENGTH"s | %"$TABLE_INFO_COLUMN_LENGTH"s | %"$TABLE_AUTHORS_COLUMN_LENGTH"s |" "$hash" "$info_line" "$authors_line"  >> $output_file
	else
		printf "\n" >> $output_file
		printf "| %"$TABLE_HASH_COLUMN_LENGTH"s | %"$TABLE_INFO_COLUMN_LENGTH"s | %"$TABLE_AUTHORS_COLUMN_LENGTH"s |" "" "$info_line" "$authors_line"  >> $output_file
	fi

	printf "\n" >> $output_file
}


# Add raw table footer
# Parameters:
# 	$1 - the output file
function add_raw_table_footer()
{
	local output_file=$1

	
	# Table footer
	printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $output_file
	printf "\n" >> $output_file
}

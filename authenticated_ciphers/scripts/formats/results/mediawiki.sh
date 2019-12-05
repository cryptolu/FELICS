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
# Functions to generate MediaWiki data table
#


# Add MediaWiki table header
# Parameters:
#     $1 - the output file
#     $2 - the scenario
#     $3 - the architecture
function add_mediawiki_table_header()
{
    local output_file=$1
    local scenario=$2
    local architecture=$3


    # Clear output
    echo -n "" > $output_file

    case $scenario in
        $SCRIPT_SCENARIO_0 | $SCRIPT_SCENARIO_1 | $SCRIPT_SCENARIO_2 | $SCRIPT_SCENARIO_3 | $SCRIPT_SCENARIO_4 | $SCRIPT_SCENARIO_5 | $SCRIPT_SCENARIO_6)
            # Table title & header
            printf "{| class=\"wikitable sortable\" style=\"margin: auto;\"" >> $output_file
            printf "\n" >> $output_file
            printf "|+ Architecture: $architecture; Scenario: $scenario" >> $output_file
            printf "\n" >> $output_file
            printf "|-" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" colspan=\"6\" rowspan=\"2\" | Cipher Info" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" colspan=\"3\" rowspan=\"2\" | Implementation Info" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" colspan=\"10\" rowspan=\"2\" | Code Size" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" colspan=\"18\" | RAM" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" colspan=\"7\" rowspan=\"2\" | Execution Time" >> $output_file
            printf "\n" >> $output_file
            printf "|-" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" colspan=\"7\" | Stack" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" colspan=\"11\" | Data" >> $output_file
            printf "\n" >> $output_file
            printf "|-" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Cipher" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Block Size (bits)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Key Size (bits)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Nonce Size (bits)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | State Size (bits)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Tag Size (bits)" >> $output_file
            printf "\n" >> $output_file

            printf "! scope=\"col\" | Version" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Language" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Options" >> $output_file
            printf "\n" >> $output_file

            printf "! scope=\"col\" | Initialize (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | PAD (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | PPD (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Finalize (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | TG (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | PCD (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | TV (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Total E (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Total D (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Total (bytes)" >> $output_file
            printf "\n" >> $output_file

            printf "! scope=\"col\" | Initialize (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | PAD (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | PPD (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Finalize (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | TG (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | PCD (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | TV (bytes)" >> $output_file
            printf "\n" >> $output_file

            printf "! scope=\"col\" | Initialize (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | PAD (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | PPD (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Finalize (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | TG (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | PCD (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | TV (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Common (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Total E (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Total D (bytes)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Total (bytes)" >> $output_file
            printf "\n" >> $output_file

            printf "! scope=\"col\" | Initialize (cycles)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | PAD (cycles)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | PPD (cycles)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | Finalize (cycles)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | TG (cycles)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | PCD (cycles)" >> $output_file
            printf "\n" >> $output_file
            printf "! scope=\"col\" | TV (cycles)" >> $output_file
            printf "\n" >> $output_file
            ;;
    esac
}


# Add MediaWiki table row
# Parameters:
#     $1 - the output file
#     $2 - the scenario
#     $3 - the cipher name
#     $4 - the cipher block size
#     $5 - the cipher key size
#     $6 - the cipher nonce size
#     $7 - the cipher state size
#     $8 - the cipher tag size
#     $9 - the cipher implementation version
#     $10 - the cipher implementation language
#     $11 - the cipher implementation compiler options
#     $12 - cipher metrics values
function add_mediawiki_table_row()
{
    local output_file=$1
    local scenario=$2
    local cipher_name=$3
    local cipher_block_size=$4
    local cipher_key_size=$5
    local cipher_nonce_size=$6
    local cipher_state_size=$7
    local cipher_tag_size=$8
    local cipher_implementation_version=$9
    local cipher_implementation_language=${10}
    local cipher_implementation_compiler_options=${11}
    local cipher_metrics_values=( ${@:12} )


    printf "|-" >> $output_file
    printf "\n" >> $output_file
    printf "! $cipher_name" >> $output_file
    printf "\n" >> $output_file
    printf "| $cipher_block_size" >> $output_file
    printf "\n" >> $output_file
    printf "| $cipher_key_size" >> $output_file
    printf "\n" >> $output_file
    printf "| $cipher_nonce_size" >> $output_file
    printf "\n" >> $output_file
    printf "| $cipher_state_size" >> $output_file
    printf "\n" >> $output_file
    printf "| $cipher_tag_size" >> $output_file
    printf "\n" >> $output_file
    printf "| $cipher_implementation_version" >> $output_file
    printf "\n" >> $output_file
    printf "| $cipher_implementation_language" >> $output_file
    printf "\n" >> $output_file
    printf "| $cipher_implementation_compiler_options" >> $output_file
    printf "\n" >> $output_file


    for value in ${cipher_metrics_values[@]}
    do
        printf "| %s" $value >> $output_file
        printf "\n" >> $output_file
    done
}


# Add MediaWiki table footer
# Parameters:
#     $1 - the output file
#     $2 - the scenario
function add_mediawiki_table_footer()
{
    local output_file=$1
    local scenario=$2


    printf "|}" >> $output_file
}

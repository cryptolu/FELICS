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
# Call this script to extract the cipher RAM consumption
#     ./cipher_ram.sh [{-h|--help}] [--version] [{-m|--mode}=[0|1]] [{-s|--scenario}=[0|1|2|3|4|5|6]] [{-a|--architecture}=[PC|AVR|MSP|ARM]] [{-t|--target}=[...]] [{-o|--output}=[...]] [{-b|build}=[0|1]] [{-co|--compiler_options}='...']
#
#    To call from a cipher build folder use:
#        ./../../../../scripts/cipher/cipher_ram.sh [options]
#
#    Options:
#        -h, --help
#            Display help information
#        --version
#            Display version information
#        -m, --mode
#            Specifies which output mode to use
#                0 - raw table for given cipher
#                1 - raw data for given cipher
#                Default: 0
#        -s, --scenario
#            Specifies which scenario is used
#                0 - cipher and debug scenario
#                1 - scenario 1a (scenario 1)
#                2 - scenario 1b (scenario 2)
#                3 - scenario 1c (scenario 3)
#                4 - scenario 2a (scenario 4)
#                5 - scenario 2b (scenario 5)
#                6 - scenario 2c (scenario 6)
#                Default: 0
#        -a, --architecture
#            Specifies which architecture is used
#                PC - binary files are build for PC
#                AVR - binary files are build for AVR device
#                MSP - binary file are build for MSP device
#                ARM - binary files are build for ARM device
#                Default: PC
#        -t, --target
#            Specifies which is the target path. The relative path is computed from the directory where script was called
#                Default: .
#        -o, --output
#            Specifies where to output the results. The relative path is computed from the directory where script was called
#                Default: /dev/tty
#        -b, --build
#            Specifies if script should build the source files
#                0 - do not build source files
#                1 - build source files
#                Default: 1
#        -co,--compiler_options
#            Specifies the compiler options
#                List of values: '-O3 --param max-unroll-times=5 --param max-unrolled-insns=100 ...'
#                Default: -O3
#
#    Examples:
#        ./../../../../scripts/cipher/cipher_ram.sh -m=0
#        ./../../../../scripts/cipher/cipher_ram.sh --mode=1 --architecture=MSP
#        ./../../../../scripts/cipher/cipher_ram.sh -o=results.txt
#        ./cipher_ram.sh -t=./../../source/ciphers/CipherName_BlockSizeInBits_KeySizeInBits_NonceSizeInBits_StateSizeInBits_TagSizeInBits_v01/build
#


# Get current script path
script_path=$(dirname $0)

# Include configuration file
source $script_path/../../../common/config/config.sh

# Include constants files
source $script_path/../constants/constants.sh
source $script_path/../constants/cipher/cipher_ram.sh

# Include help file
source $script_path/../help/cipher/cipher_ram.sh

# Include validation functions
source $script_path/../common/validate.sh

# Include version file
source $script_path/../common/version.sh


# Default values
SCRIPT_MODE=$SCRIPT_MODE_0
SCRIPT_SCENARIO=$SCRIPT_SCENARIO_0
SCRIPT_ARCHITECTURE=$SCRIPT_ARCHITECTURE_PC
SCRIPT_TARGET=$DEFAULT_SCRIPT_TARGET
SCRIPT_OUTPUT=$DEFAULT_SCRIPT_OUTPUT
SCRIPT_BUILD=$SCRIPT_BUILD_ENABLED
SCRIPT_COMPILER_OPTIONS=$SCRIPT_COMPILER_OPTION_OPTIMIZE_3


# Parse script arguments
for i in "$@"
do
    case $i in
        -h|--help)
            display_help
            shift
            ;;
        --version)
            display_version
            shift
            ;;
        -m=*|--mode=*)
            SCRIPT_MODE="${i#*=}"
            shift
            ;;
        -s=*|--scenario=*)
            SCRIPT_SCENARIO="${i#*=}"
            shift
            ;;
        -a=*|--architecture=*)
            SCRIPT_ARCHITECTURE="${i#*=}"
            shift
            ;;
        -t=*|--target=*)
            if [[ "${i#*=}" ]] ; then
                SCRIPT_TARGET="${i#*=}"
            fi
            shift
            ;;
        -o=*|--output=*)
            if [[ "${i#*=}" ]] ; then
                SCRIPT_OUTPUT="${i#*=}"
            fi
            shift
            ;;
        -b=*|--build=*)
            SCRIPT_BUILD="${i#*=}"
            shift
            ;;
        -co=*|--compiler_options=*)
            SCRIPT_COMPILER_OPTIONS="${i#*=}"
            shift
            ;;
        *)
            # Unknown option
            ;;
    esac
done


echo "Script settings:"
echo -e "\t SCRIPT_MODE \t\t\t = $SCRIPT_MODE"
echo -e "\t SCRIPT_SCENARIO \t\t = $SCRIPT_SCENARIO"
echo -e "\t SCRIPT_ARCHITECTURE \t\t = $SCRIPT_ARCHITECTURE"
echo -e "\t SCRIPT_TARGET \t\t\t = $SCRIPT_TARGET"
echo -e "\t SCRIPT_OUTPUT \t\t\t = $SCRIPT_OUTPUT"
echo -e "\t SCRIPT_BUILD \t\t\t = $SCRIPT_BUILD"
echo -e "\t SCRIPT_COMPILER_OPTIONS \t = $SCRIPT_COMPILER_OPTIONS"


# Validate inputs
validate_mode $SCRIPT_MODE
validate_scenario $SCRIPT_SCENARIO
validate_architecture $SCRIPT_ARCHITECTURE


if [ $SCRIPT_BUILD_ENABLED -eq $SCRIPT_BUILD ] ; then
    $script_path/../common/build.sh -a=$SCRIPT_ARCHITECTURE -s=$SCRIPT_SCENARIO -co="$SCRIPT_COMPILER_OPTIONS" -v=$SCRIPT_VERBOSE_DISABLED
fi


# Simulate the given binary file execution
# Parameters:
#     $1 - the gdb command file
#     $2 - the gdb target binary file
#     $3 - the gdb output file
#     $4 - the simulator output file
#     $5 - the make log file
function simulate()
{
    local command_file=$1
    local target_file=$2
    local gdb_output_file=$3
    local simulator_output_file=$4
    local make_log_file=$5


    case $SCRIPT_ARCHITECTURE in
        $SCRIPT_ARCHITECTURE_PC)
            $PC_GDB -x $command_file $target_file &> $gdb_output_file &
            ;;
        $SCRIPT_ARCHITECTURE_AVR)
            $SIMAVR_SIMULATOR -g -m atmega128 $target_file &> $simulator_output_file &
            $AVR_GDB -x $command_file &> $gdb_output_file

            simavr_pid=$(ps aux | grep "$SIMAVR_SIMULATOR -g -m atmega128 $target_file" | grep -v "grep" | tr -s ' ' | cut -d ' ' -f 2)
            for pid in $simavr_pid
            do
                kill -PIPE $pid
            done
            ;;
        $SCRIPT_ARCHITECTURE_MSP)
            $MSPDEBUG_SIMULATOR -n sim "prog $target_file" gdb &> $simulator_output_file &
            $MSP_GDB -x $command_file &> $gdb_output_file
            ;;
        $SCRIPT_ARCHITECTURE_ARM)
            # Upload the program to the board
            if [ $SCRIPT_SCENARIO_0 == $SCRIPT_SCENARIO ] ; then
                make -f ./../../../common/cipher.mk ARCHITECTURE=$SCRIPT_ARCHITECTURE SCENARIO=$SCRIPT_SCENARIO upload-cipher &> $make_log_file
            else
                make -f ./../../../common/cipher.mk ARCHITECTURE=$SCRIPT_ARCHITECTURE SCENARIO=$SCRIPT_SCENARIO upload-scenario &> $make_log_file
            fi

            # Try to start JLinkGDBServer
            start_attempts=0
            while true
            do
                $JLINK_GDB_SERVER -device cortex-m3 &> $simulator_output_file &
                sleep 1
                jlink_gdb_server_pid=$(ps aux | grep "JLinkGDBServer" | grep -v "grep" | tr -s ' ' | cut -d ' ' -f 2)
                if [ ! -z $jlink_gdb_server_pid ]; then
                    break
                else
                    start_attempts=$((start_attempts + 1))
                    if [ MAX_JLINK_GDB_SERVER_START_ATTEMPTS -eq $start_attempts ] ; then
                        break
                    fi
                fi
            done

            $ARM_GDB -x $command_file &> $gdb_output_file

            jlink_gdb_server_pid=$(ps aux | grep "JLinkGDBServer" | grep -v "grep" | tr -s ' ' | cut -d ' ' -f 2)
            for pid in $jlink_gdb_server_pid
            do
                kill -PIPE $pid
            done
            ;;
    esac

    # Wait for the debug session to finish
    sleep 1
}


# Compute the stack usage
# Parameters:
#     $1 - the gdb output file
#     $2 - the gdb printed variable name
function compute_stack_usage()
{
    local output_file=$1
    local variable_name=$2


    # Get the stack content array
    local stack_content=( $(cat $output_file | nawk '/\$'$variable_name' = {/,/}/' | tr -d '\r' | cut -d '{' -f 2 | cut -d '}' -f 1 | tr -d ',') )

    local count=0
    while [ $((${stack_content[$count]})) -eq $((${MEMORY_PATTERN[$(($count % $memory_patern_length))]})) ]
    do
        count=$(($count + 1));
    done

    local used_stack=$(($MEMORY_SIZE - $count))

    echo $used_stack
}


# Set the current working directory
current_directory=$(pwd)
echo "Begin cipher RAM - $current_directory"


# Change relative script output path
if [[ $SCRIPT_OUTPUT != /* ]] ; then
    SCRIPT_OUTPUT=$current_directory/$SCRIPT_OUTPUT
fi


# Change current working directory
cd $SCRIPT_TARGET
echo "Changed working directory: $(pwd)"


# Get block, key, nonce state, tag sizes
block_size=$(cat $CONSTANTS_SOURCE_FILE | grep "$BLOCK_SIZE_DEFINE" | tr -d '\r' | cut -d ' ' -f 3)
key_size=$(cat $CONSTANTS_SOURCE_FILE | grep "$KEY_SIZE_DEFINE" | tr -d '\r' | cut -d ' ' -f 3)
nonce_size=$(cat $CONSTANTS_SOURCE_FILE | grep "$NONCE_SIZE_DEFINE" | tr -d '\r' | cut -d ' ' -f 3)
state_size=$(cat $CONSTANTS_SOURCE_FILE | grep "$STATE_SIZE_DEFINE" | tr -d '\r' | cut -d ' ' -f 3)
tag_size=$(cat $CONSTANTS_SOURCE_FILE | grep "$TAG_SIZE_DEFINE" | tr -d '\r' | cut -d ' ' -f 3)

test_message_size=$(cat $CONSTANTS_SOURCE_FILE | grep "$TEST_MESSAGE_SIZE_DEFINE" | tr -d '\r' | cut -d ' ' -f 3)
test_associated_data_size=$(cat $CONSTANTS_SOURCE_FILE | grep "$TEST_ASSOCIATED_DATA_SIZE_DEFINE" | tr -d '\r' | cut -d ' ' -f 3)

message_size=$(cat $CIPHER_HEADER_FILE | grep -A 2 "SCENARIO_${SCRIPT_SCENARIO} == SCENARIO" | grep "$MESSAGE_SIZE_DEFINE" | cut -d ' ' -f 3)
associated_data_size=$(cat $CIPHER_HEADER_FILE | grep -A 2 "SCENARIO_${SCRIPT_SCENARIO} == SCENARIO" | grep "$ASSOCIATED_DATA_SIZE_DEFINE" | cut -d ' ' -f 3)

if [ "TEST_MESSAGE_SIZE" == $message_size ]; then
    # This is scenario 0
    if [ "BLOCK_SIZE" == $test_message_size ]; then
        #this is normal testing scenario
        message_size=$block_size
    else
        # This is a padding scenario
        message_size=$test_message_size
    fi
fi

if [ "TEST_ASSOCIATED_DATA_SIZE" == $associated_data_size ]; then
    # This is scenario 0
    if [ "BLOCK_SIZE" == $test_associated_data_size ]; then
        # This is normal testing scenario
        associated_data_size=$block_size
    else
        # This is a padding scenario
        associated_data_size=$test_associated_data_size
    fi
fi


# Set the searched files pattern
pattern=$ALL_FILES$OBJECT_FILE_EXTENSION

# Get the number of files matching the pattern
files_number=$(find . -maxdepth 1 -type f -name "$pattern" | wc -l)

if [ 0 -eq $files_number ] ; then
    echo "There is no file matching the pattern: '$pattern' for cipher '$cipher_name'!"
    echo "Exit!"
    exit
fi

# Get the files matching the pattern
files=$(ls $pattern)


# Add scenario *.elf file to the files
case $SCRIPT_SCENARIO in
    $SCRIPT_SCENARIO_0)
        files="$CIPHER_FILE$ELF_FILE_EXTENSION $files"
        ;;

    $SCRIPT_SCENARIO_1)
        files="$SCENARIO1_FILE$ELF_FILE_EXTENSION $files"
        ;;

    $SCRIPT_SCENARIO_2)
        files="$SCENARIO2_FILE$ELF_FILE_EXTENSION $files"
        ;;

    $SCRIPT_SCENARIO_3)
        files="$SCENARIO3_FILE$ELF_FILE_EXTENSION $files"
        ;;

    $SCRIPT_SCENARIO_4)
        files="$SCENARIO4_FILE$ELF_FILE_EXTENSION $files"
        ;;
    $SCRIPT_SCENARIO_5)
        files="$SCENARIO5_FILE$ELF_FILE_EXTENSION $files"
        ;;
    $SCRIPT_SCENARIO_6)
        files="$SCENARIO6_FILE$ELF_FILE_EXTENSION $files"
        ;;
esac


# Set the size command depending on the architecture
case $SCRIPT_ARCHITECTURE in
    $SCRIPT_ARCHITECTURE_PC)
        script_size=$PC_SIZE
        ;;

    $SCRIPT_ARCHITECTURE_AVR)
        script_size=$AVR_SIZE
        ;;

    $SCRIPT_ARCHITECTURE_MSP)
        script_size=$MSP_SIZE
        ;;

    $SCRIPT_ARCHITECTURE_ARM)
        script_size=$ARM_SIZE
        ;;
esac


for file in $files
do
    # Get the section sizes line for current file
    if [ -e $file ] ; then
        size=$($script_size $file | grep $file)
    else
        continue
    fi

    # Get the section data size
    data=$(echo $size | cut -d ' ' -f 2)

    # Get the component name (file name without the extension)
    component=${file%$OBJECT_FILE_EXTENSION}
    if [ "$component" == "$file" ] ; then
        component=${file%$ELF_FILE_EXTENSION}
    fi

    declare $component"_data"=$data
done


shared_constants_ini=0
shared_constants_pad=0
shared_constants_ppd=0
shared_constants_fin=0
shared_constants_tg=0
shared_constants_pcd=0
shared_constants_tv=0
shared_constants_e_total=0
shared_constants_d_total=0
shared_constants_total=0

# Read and process constants implementation information
declare -a shared_parts_e
declare -a shared_parts_d
declare -a shared_parts
for constants_section in ${CONSTANTS_SECTIONS[@]}
do
    shared_files=$(cat $IMPLEMENTATION_INFO_FILE | grep $constants_section$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 | tr ',' ' ')

    for shared_file in $shared_files
    do
        shared_name=$shared_file"_data"

        shared_value=${!shared_name}
        if [ "" == "$shared_value" ] ; then
            shared_value=0
        fi


        # Test if the shared file RAM was added to the total
        used_part=$FALSE
        for shared_part in ${shared_parts[@]}
        do
            if [ "$shared_part" == "$shared_file" ] ; then
                used_part=$TRUE
                break
            fi
        done


        # Add the shared file ROM to total
        if [ $FALSE -eq $used_part ]; then
            shared_constants_total=$(($shared_constants_total + $shared_value))
            shared_parts+=($shared_file)
        fi


        # Total constants encryption - begin

        # Check if this constants section is used in encryption
        used_constants_section=$FALSE
        for constants_section_e in ${CONSTANTS_SECTIONS_ENCRYPT[@]}
        do
            if [ "$constants_section_e" == "$constants_section" ] ; then
                used_constants_section=$TRUE
                break
            fi
        done

        if [ $TRUE -eq $used_constants_section ] ; then
            # Test if the shared file ROM was added to the encryption total
            used_part=$FALSE
            for shared_part in ${shared_parts_e[@]}
            do
                if [ "$shared_part" == "$shared_file" ] ; then
                    used_part=$TRUE
                    break
                fi
            done


            # Add the shared file ROM to encryption total
            if [ $FALSE -eq $used_part ]; then
                shared_constants_e_total=$(($shared_constants_e_total + $shared_value))
                shared_parts_e+=($shared_file)
            fi
        fi

        # Total constants encryption - end


        # Total constants decryption - begin

        # Check if this constants section is used in encryption
        used_constants_section=$FALSE
        for constants_section_d in ${CONSTANTS_SECTIONS_DECRYPT[@]}
        do
            if [ "$constants_section_d" == "$constants_section" ] ; then
                used_constants_section=$TRUE
                break
            fi
        done

        if [ $TRUE -eq $used_constants_section ] ; then
            # Test if the shared file ROM was added to the decryption total
            used_part=$FALSE
            for shared_part in ${shared_parts_d[@]}
            do
                if [ "$shared_part" == "$shared_file" ] ; then
                    used_part=$TRUE
                    break
                fi
            done


            # Add the shared file ROM to decryption total
            if [ $FALSE -eq $used_part ]; then
                shared_constants_d_total=$(($shared_constants_d_total + $shared_value))
                shared_parts_d+=($shared_file)
            fi
        fi

        # Total constants decryption - end


        case $constants_section in
            $CONSTANTS_SECTION_INI)
                shared_constants_ini=$(($shared_constants_ini + $shared_value))
                ;;
            $CONSTANTS_SECTION_PAD)
                shared_constants_pad=$(($shared_constants_pad + $shared_value))
                ;;
            $CONSTANTS_SECTION_PPD)
                shared_constants_ppd=$(($shared_constants_ppd + $shared_value))
                ;;
            $CONSTANTS_SECTION_FIN)
                shared_constants_fin=$(($shared_constants_fin + $shared_value))
                ;;
            $CONSTANTS_SECTION_TG)
                shared_constants_tg=$(($shared_constants_tg + $shared_value))
                ;;
            $CONSTANTS_SECTION_PCD)
                shared_constants_pcd=$(($shared_constants_pcd + $shared_value))
                ;;
        esac
    done
done


    data_ram_ini=$shared_constants_ini
    data_ram_pad=$shared_constants_pad
    data_ram_ppd=$shared_constants_ppd
    data_ram_fin=$shared_constants_fin
    data_ram_tg=$shared_constants_tg
    data_ram_pcd=$shared_constants_pcd
    data_ram_tv=0


# Compute the data RAM
case $SCRIPT_SCENARIO in
    $SCRIPT_SCENARIO_0)
        data_ram_common=$(($key_size + $state_size + $tag_size + $nonce_size + $message_size + $associated_data_size))
        ;;
    $SCRIPT_SCENARIO_1)
        data_ram_common=$(($key_size + $state_size + $tag_size + $nonce_size + $message_size + $associated_data_size))
        ;;
    $SCRIPT_SCENARIO_2)
        data_ram_common=$(($key_size + $state_size + $tag_size + $nonce_size + $message_size + $associated_data_size))
        ;;
    $SCRIPT_SCENARIO_3)
        data_ram_common=$(($key_size + $state_size + $nonce_size + $message_size + $associated_data_size))
        ;;
    $SCRIPT_SCENARIO_4)
        data_ram_common=$(($key_size + $state_size + $tag_size + $nonce_size + $message_size + $associated_data_size))
        ;;
    $SCRIPT_SCENARIO_5)
        data_ram_common=$(($key_size + $state_size + $tag_size + $nonce_size + $message_size + $associated_data_size))
        ;;
    $SCRIPT_SCENARIO_6)
        data_ram_common=$(($key_size + $state_size + $tag_size + $nonce_size + $message_size + $associated_data_size))
        ;;
esac

data_ram_total=$(($data_ram_common + $shared_constants_total))
data_ram_e_total=$(($data_ram_common + $shared_constants_e_total))
data_ram_d_total=$(($data_ram_common + $shared_constants_d_total))


# Get the memory pattern length
memory_patern_length=$((${#MEMORY_PATTERN[@]}))

# Generate the memory file
memory_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MEMORY_FILE
echo "Generate the memory file: '$memory_file'"
echo -n "" > $memory_file

for ((i=0; i<$MEMORY_SIZE/$memory_patern_length; i++))
do
    echo -ne "$(printf '\\x%x\\x%x\\x%x\\x%x\\x%x\\x%x\\x%x\\x%x\\x%x\\x%x' ${MEMORY_PATTERN[*]})" >> $memory_file
done


# Get the cipher name
cipher_name=$(basename -- "$(dirname -- "$(pwd)")")


# Set the searched file pattern
case $SCRIPT_SCENARIO in
    $SCRIPT_SCENARIO_0)
        file=$CIPHER_FILE$ELF_FILE_EXTENSION
        ;;

    $SCRIPT_SCENARIO_1)
        file=$SCENARIO1_FILE$ELF_FILE_EXTENSION
        ;;

    $SCRIPT_SCENARIO_2)
        file=$SCENARIO2_FILE$ELF_FILE_EXTENSION
        ;;

    $SCRIPT_SCENARIO_3)
        file=$SCENARIO3_FILE$ELF_FILE_EXTENSION
        ;;

    $SCRIPT_SCENARIO_4)
        file=$SCENARIO4_FILE$ELF_FILE_EXTENSION
        ;;

    $SCRIPT_SCENARIO_5)
        file=$SCENARIO5_FILE$ELF_FILE_EXTENSION
        ;;

    $SCRIPT_SCENARIO_6)
        file=$SCENARIO6_FILE$ELF_FILE_EXTENSION
        ;;
esac


# Get the number of files matching the pattern
files_number=$(find . -maxdepth 1 -type f -name "$file" | wc -l)

if [ 0 -eq $files_number ] ; then
    echo "There is no file matching the pattern: '$file' for cipher '$cipher_name'!"
    echo "Exit!"
    exit
fi


gdb_stack_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$GDB_STACK_LOG_FILE
gdb_stack_sections_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$GDB_STACK_SECTIONS_LOG_FILE

# Debug the executable
case $SCRIPT_ARCHITECTURE in
    $SCRIPT_ARCHITECTURE_PC)

        case $SCRIPT_SCENARIO in
            $SCRIPT_SCENARIO_0)
                simulate $PC_CIPHER_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file
                simulate $PC_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_1)
                simulate $PC_SCENARIO1_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file
                simulate $PC_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_2)
                simulate $PC_SCENARIO2_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file
                simulate $PC_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_3)
                simulate $PC_SCENARIO3_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file
                simulate $PC_SCENARIO3_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_4)
                simulate $PC_SCENARIO4_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file
                simulate $PC_SCENARIO4_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_5)
                simulate $PC_SCENARIO5_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file
                simulate $PC_SCENARIO5_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_6)
                simulate $PC_SCENARIO6_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file
                simulate $PC_SCENARIO6_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file
                ;;
        esac
        ;;

    $SCRIPT_ARCHITECTURE_AVR)

        simavr_stack_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$SIMAVR_STACK_LOG_FILE
        simavr_stack_sections_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$SIMAVR_STACK_SECTIONS_LOG_FILE

        case $SCRIPT_SCENARIO in
            $SCRIPT_SCENARIO_0)
                simulate $AVR_CIPHER_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $simavr_stack_log_file
                simulate $AVR_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $simavr_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_1)
                simulate $AVR_SCENARIO1_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $simavr_stack_log_file
                simulate $AVR_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $simavr_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_2)
                simulate $AVR_SCENARIO2_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $simavr_stack_log_file
                simulate $AVR_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $simavr_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_3)
                simulate $AVR_SCENARIO3_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $simavr_stack_log_file
                simulate $AVR_SCENARIO3_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $simavr_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_4)
                simulate $AVR_SCENARIO4_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $simavr_stack_log_file
                simulate $AVR_SCENARIO4_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $simavr_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_5)
                simulate $AVR_SCENARIO5_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $simavr_stack_log_file
                simulate $AVR_SCENARIO5_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $simavr_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_6)
                simulate $AVR_SCENARIO6_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $simavr_stack_log_file
                simulate $AVR_SCENARIO6_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $simavr_stack_sections_log_file
                ;;
        esac

        if [ $FALSE -eq $KEEP_GENERATED_FILES ] ; then
            # Remove log files
            rm -f $simavr_stack_log_file
            rm -f $simavr_stack_sections_log_file
        fi
        ;;

    $SCRIPT_ARCHITECTURE_MSP)

        mspdebug_stack_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MSPDEBUG_STACK_LOG_FILE
        mspdebug_stack_sections_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MSPDEBUG_STACK_SECTIONS_LOG_FILE

        case $SCRIPT_SCENARIO in
            $SCRIPT_SCENARIO_0)
                simulate $MSP_CIPHER_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $mspdebug_stack_log_file
                simulate $MSP_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $mspdebug_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_1)
                simulate $MSP_SCENARIO1_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $mspdebug_stack_log_file
                simulate $MSP_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $mspdebug_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_2)
                simulate $MSP_SCENARIO2_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $mspdebug_stack_log_file
                simulate $MSP_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $mspdebug_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_3)
                simulate $MSP_SCENARIO3_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $mspdebug_stack_log_file
                simulate $MSP_SCENARIO3_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $mspdebug_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_4)
                simulate $MSP_SCENARIO4_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $mspdebug_stack_log_file
                simulate $MSP_SCENARIO4_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $mspdebug_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_5)
                simulate $MSP_SCENARIO5_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $mspdebug_stack_log_file
                simulate $MSP_SCENARIO5_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $mspdebug_stack_sections_log_file
                ;;
            $SCRIPT_SCENARIO_6)
                simulate $MSP_SCENARIO6_GDB_STACK_COMMANDS_FILE $file $gdb_stack_log_file $mspdebug_stack_log_file
                simulate $MSP_SCENARIO6_GDB_STACK_SECTIONS_COMMANDS_FILE $file $gdb_stack_sections_log_file $mspdebug_stack_sections_log_file
                ;;
        esac

        if [ $FALSE -eq $KEEP_GENERATED_FILES ] ; then
            # Remove log files
            rm -f $mspdebug_stack_log_file
            rm -f $mspdebug_stack_sections_log_file
        fi
        ;;

    $SCRIPT_ARCHITECTURE_ARM)

        make_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$MAKE_LOG_FILE
        jlink_gdb_server_stack_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$JLINK_GDB_SERVER_STACK_LOG_FILE
        jlink_gdb_server_stack_sections_log_file=$SCRIPT_ARCHITECTURE$SCENARIO_NAME_PART$SCRIPT_SCENARIO$FILE_NAME_SEPARATOR$JLINK_GDB_SERVER_STACK_SECTIONS_LOG_FILE

        case $SCRIPT_SCENARIO in
            $SCRIPT_SCENARIO_0)
                simulate $ARM_CIPHER_GDB_STACK_COMMANDS_FILE $ARM_TARGET_FILE $gdb_stack_log_file $jlink_gdb_server_stack_log_file $make_log_file
                simulate $ARM_CIPHER_GDB_STACK_SECTIONS_COMMANDS_FILE $ARM_TARGET_FILE $gdb_stack_sections_log_file $jlink_gdb_server_stack_sections_log_file $make_log_file
                ;;
            $SCRIPT_SCENARIO_1)
                simulate $ARM_SCENARIO1_GDB_STACK_COMMANDS_FILE $ARM_TARGET_FILE $gdb_stack_log_file $jlink_gdb_server_stack_log_file $make_log_file
                simulate $ARM_SCENARIO1_GDB_STACK_SECTIONS_COMMANDS_FILE $ARM_TARGET_FILE $gdb_stack_sections_log_file $jlink_gdb_server_stack_sections_log_file $make_log_file
                ;;
            $SCRIPT_SCENARIO_2)
                simulate $ARM_SCENARIO2_GDB_STACK_COMMANDS_FILE $ARM_TARGET_FILE $gdb_stack_log_file $jlink_gdb_server_stack_log_file $make_log_file
                simulate $ARM_SCENARIO2_GDB_STACK_SECTIONS_COMMANDS_FILE $ARM_TARGET_FILE $gdb_stack_sections_log_file $jlink_gdb_server_stack_sections_log_file $make_log_file
                ;;
            $SCRIPT_SCENARIO_3)
                simulate $ARM_SCENARIO3_GDB_STACK_COMMANDS_FILE $ARM_TARGET_FILE $gdb_stack_log_file $jlink_gdb_server_stack_log_file $make_log_file
                simulate $ARM_SCENARIO3_GDB_STACK_SECTIONS_COMMANDS_FILE $ARM_TARGET_FILE $gdb_stack_sections_log_file $jlink_gdb_server_stack_sections_log_file $make_log_file
                ;;
            $SCRIPT_SCENARIO_4)
                simulate $ARM_SCENARIO4_GDB_STACK_COMMANDS_FILE $ARM_TARGET_FILE $gdb_stack_log_file $jlink_gdb_server_stack_log_file $make_log_file
                simulate $ARM_SCENARIO4_GDB_STACK_SECTIONS_COMMANDS_FILE $ARM_TARGET_FILE $gdb_stack_sections_log_file $jlink_gdb_server_stack_sections_log_file $make_log_file
                ;;
            $SCRIPT_SCENARIO_5)
                simulate $ARM_SCENARIO5_GDB_STACK_COMMANDS_FILE $ARM_TARGET_FILE $gdb_stack_log_file $jlink_gdb_server_stack_log_file $make_log_file
                simulate $ARM_SCENARIO5_GDB_STACK_SECTIONS_COMMANDS_FILE $ARM_TARGET_FILE $gdb_stack_sections_log_file $jlink_gdb_server_stack_sections_log_file $make_log_file
                ;;
            $SCRIPT_SCENARIO_6)
                simulate $ARM_SCENARIO6_GDB_STACK_COMMANDS_FILE $ARM_TARGET_FILE $gdb_stack_log_file $jlink_gdb_server_stack_log_file $make_log_file
                simulate $ARM_SCENARIO6_GDB_STACK_SECTIONS_COMMANDS_FILE $ARM_TARGET_FILE $gdb_stack_sections_log_file $jlink_gdb_server_stack_sections_log_file $make_log_file
                ;;
        esac

        if [ $FALSE -eq $KEEP_GENERATED_FILES ] ; then
            # Remove log files
            rm -f $make_log_file
            rm -f $jlink_gdb_server_stack_log_file
            rm -f $jlink_gdb_server_stack_sections_log_file
        fi
        ;;
esac

ini_stack=0
pad_stack=0
ppd_stack=0
fin_stack=0
tg_stack=0
pcd_stack=0
tv_stack=0
total_stack=0

if [ -f $gdb_stack_log_file ] ; then
    total_stack=$(compute_stack_usage $gdb_stack_log_file 1)
fi

if [ -f $gdb_stack_sections_log_file ] ; then
    if [ $SCRIPT_SCENARIO_1 -ne $SCRIPT_SCENARIO ] || [ $SCRIPT_SCENARIO_4 -ne $SCRIPT_SCENARIO ] ; then
        ini_stack=$(compute_stack_usage $gdb_stack_sections_log_file 1)
        pad_stack=$(compute_stack_usage $gdb_stack_sections_log_file 2)
        ppd_stack=$(compute_stack_usage $gdb_stack_sections_log_file 3)
        fin_stack=$(compute_stack_usage $gdb_stack_sections_log_file 4)
         tg_stack=$(compute_stack_usage $gdb_stack_sections_log_file 5)
        pcd_stack=$(compute_stack_usage $gdb_stack_sections_log_file 8)
         tv_stack=$(compute_stack_usage $gdb_stack_sections_log_file 10)
    else
        ini_stack=$(compute_stack_usage $gdb_stack_sections_log_file 1)
        pad_stack=$(compute_stack_usage $gdb_stack_sections_log_file 2)
        ppd_stack=$(compute_stack_usage $gdb_stack_sections_log_file 3)
        fin_stack=0
        tg_stack=0
        pcd_stack=$(compute_stack_usage $gdb_stack_sections_log_file 6)
        tv_stack=0
    fi
fi


if [ $FALSE -eq $KEEP_GENERATED_FILES ] ; then
    # Remove memory and gdb log files
    rm -f $memory_file
    rm -f $gdb_stack_log_file
    rm -f $gdb_stack_sections_log_file
fi


# Check if encryption/decryption key schedule is used
use_finalization=$(cat $IMPLEMENTATION_INFO_FILE | grep $USE_FINALIZATION$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 |  tr -d '[[:space:]]')

# Convert to lowercase
use_finalization=${use_finalization,,}

if [ $USE_FINALIZATION_NO == "$use_finalization" ] ; then
    fin_stack=0
fi

# Check if this cipher processes empty assciated data or plaintext
process_empty_associated_data=$(cat $IMPLEMENTATION_INFO_FILE | grep $PROCESS_EMPTY_ASSOCIATED_DATA$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 |  tr -d '[[:space:]]')
process_empty_message=$(cat $IMPLEMENTATION_INFO_FILE | grep $PROCESS_EMPTY_MESSAGE$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 |  tr -d '[[:space:]]')

if [ $SCRIPT_SCENARIO_1 -eq $SCRIPT_SCENARIO ] && [ $PROCESS_EMPTY_ASSOCIATED_DATA_NO == "$process_empty_associated_data" ] ; then
    pad_stack=0
fi

if [ $SCRIPT_SCENARIO_4 -eq $SCRIPT_SCENARIO ] && [ $PROCESS_EMPTY_ASSOCIATED_DATA_NO == "$process_empty_associated_data" ] ; then
    pad_stack=0
fi

if [ $SCRIPT_SCENARIO_2 -eq $SCRIPT_SCENARIO ] && [ $PROCESS_EMPTY_MESSAGE_NO == "$process_empty_message" ]; then
    ppd_stack=0
    pcd_stack=0
fi

if [ $SCRIPT_SCENARIO_5 -eq $SCRIPT_SCENARIO ] && [ $PROCESS_EMPTY_MESSAGE_NO == "$process_empty_message" ]; then
    ppd_stack=0
    pcd_stack=0
fi

# Dipslay results
if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
    # Clear output
    echo -n "" > $SCRIPT_OUTPUT

    # Table header
    printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $SCRIPT_OUTPUT
    printf "\n" >> $SCRIPT_OUTPUT
    printf "| %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s |\n" "Block Size" "Key Size" "Nonce Size" "State Size" "Tag Size" "Data RAM" "Scenario" "Initialize" "PAD" "PPD" "Finalize" "TG" "PCD" "TV" >> $SCRIPT_OUTPUT
    printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $SCRIPT_OUTPUT
    printf "\n" >> $SCRIPT_OUTPUT

    # Table line
    printf "| %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s | %10s |\n" $block_size $key_size $nonce_size $state_size $tag_size $data_ram_total $total_stack $ini_stack $pad_stack $ppd_stack $fin_stack $tg_stack $pcd_stack $tv_stack  >> $SCRIPT_OUTPUT

    # Table footer
    printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $SCRIPT_OUTPUT
    printf "\n" >> $SCRIPT_OUTPUT
else
    printf "%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s" $ini_stack $pad_stack $ppd_stack $fin_stack $tg_stack $pcd_stack $tv_stack $data_ram_ini $data_ram_pad $data_ram_ppd $data_ram_fin $data_ram_tg $data_ram_pcd $data_ram_tv $data_ram_common $data_ram_e_total $data_ram_d_total $data_ram_total > $SCRIPT_OUTPUT
fi


# Change current working directory
cd $current_directory
if [ $SCRIPT_MODE_0 -ne $SCRIPT_MODE ] ; then
    echo ""
fi
echo "End cipher RAM - $(pwd)"

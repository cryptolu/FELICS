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
# Call this script to extract the cipher code size
#     ./cipher_code_size.sh [{-h|--help}] [--version] [{-m|--mode}=[0|1]] [{-s|--scenario}=[0|1|2|3|4|5|6]] [{-a|--architecture}=[PC|AVR|MSP|ARM]] [{-t|--target}=[...]] [{-o|--output}=[...]] [{-b|build}=[0|1]] [{-co|--compiler_options}='...']
#
#    To call from a cipher build folder use:
#        ./../../../../scripts/cipher/cipher_code_size.sh [options]
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
#        ./../../../../scripts/cipher/cipher_code_size.sh -m=0
#        ./../../../../scripts/cipher/cipher_code_size.sh --mode=1 --architecture=MSP
#        ./../../../../scripts/cipher/cipher_code_size.sh -o=results.txt
#        ./cipher_code_size.sh -t=./../../source/ciphers/CipherName_BlockSizeInBits_KeySizeInBits_NonceSizeInBits_StateSizeInBits_TagSizeInBits_v01/build
#


# Get current script path
script_path=$(dirname $0)

# Include configuration file
source $script_path/../../../common/config/config.sh

# Include constants files
source $script_path/../constants/constants.sh
source $script_path/../constants/cipher/cipher_code_size.sh

# Include help file
source $script_path/../help/cipher/cipher_code_size.sh

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


# Set the current working directory
current_directory=$(pwd)
echo "Begin cipher code size - $current_directory"


# Change relative script output path
if [[ $SCRIPT_OUTPUT != /* ]] ; then
    SCRIPT_OUTPUT=$current_directory/$SCRIPT_OUTPUT
fi


# Change current working directory
cd $SCRIPT_TARGET
echo "Changed working directory: $(pwd)"


# Get the cipher name
cipher_name=$(basename -- "$(dirname -- "$(pwd)")")


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


if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
    # Clear output
    echo -n "" > $SCRIPT_OUTPUT

    # Table header
    printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $SCRIPT_OUTPUT
    printf "\n" >> $SCRIPT_OUTPUT
    printf "| %-33s | %10s | %10s | %10s | %10s | %10s |\n" "Component" "ROM" "text" "data" "bss" "dec" >> $SCRIPT_OUTPUT
    printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $SCRIPT_OUTPUT
    printf "\n" >> $SCRIPT_OUTPUT
fi


for file in $files
do
    # Get the section sizes line for current file
    if [ -e $file ] ; then
        size=$($script_size $file | grep $file)
    else
        continue
    fi

    # Get the section sizes
    text=$(echo $size | cut -d ' ' -f 1)
    data=$(echo $size | cut -d ' ' -f 2)
    bss=$(echo $size | cut -d ' ' -f 3)
    dec=$(echo $size | cut -d ' ' -f 4)

    # Compute the ROM requirement
    rom=$(($text + $data))


    # Get the component name (file name without the extension)
    component=${file%$OBJECT_FILE_EXTENSION}
    if [ "$component" == "$file" ] ; then
        component=${file%$ELF_FILE_EXTENSION}
    fi


    if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
        # Table line
        printf "| %-33s | %10s | %10s | %10s | %10s | %10s |\n" $component $rom $text $data $bss $dec >> $SCRIPT_OUTPUT
    else
        # Set the component section sizes
        declare $component"_text"=$text
        declare $component"_data"=$data
        declare $component"_bss"=$bss
        declare $component"_dec"=$dec

        # Set the component ROM requirement
        declare $component"_rom"=$rom
    fi
done


if [ $SCRIPT_MODE_0 -ne $SCRIPT_MODE ] ; then
    shared_code_ini=0
    shared_code_pad=0
    shared_code_ppd=0
    shared_code_fin=0
    shared_code_tg=0
    shared_code_pcd=0
    shared_code_e_total=0
    shared_code_d_total=0
    shared_code_total=0

    # Read and process code implementation information
    declare -a shared_parts_e
    declare -a shared_parts_d
    declare -a shared_parts
    for code_section in ${CODE_SECTIONS[@]}
    do
        shared_files=$(cat $IMPLEMENTATION_INFO_FILE | grep $code_section$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 | tr ',' ' ')

        for shared_file in $shared_files
        do
            shared_name=$shared_file"_rom"

            shared_value=${!shared_name}
            if [ "" == "$shared_value" ] ; then
                shared_value=0
            fi


            # Test if the shared file ROM was added to the total
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
                shared_code_total=$(($shared_code_total + $shared_value))
                shared_parts+=($shared_file)
            fi


            # Total code encryption - begin

            # Check if this code section is used in encryption
            used_code_section=$FALSE
            for code_section_e in ${CODE_SECTIONS_ENCRYPT[@]}
            do
                if [ "$code_section_e" == "$code_section" ] ; then
                    used_code_section=$TRUE
                    break
                fi
            done

            if [ $TRUE -eq $used_code_section ] ; then
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
                    shared_code_e_total=$(($shared_code_e_total + $shared_value))
                    shared_parts_e+=($shared_file)
                fi
            fi

            # Total code encryption - end


            # Total code decryption - begin

            # Check if this code section is used in encryption
            used_code_section=$FALSE
            for code_section_d in ${CODE_SECTIONS_DECRYPT[@]}
            do
                if [ "$code_section_d" == "$code_section" ] ; then
                    used_code_section=$TRUE
                    break
                fi
            done

            if [ $TRUE -eq $used_code_section ] ; then
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
                    shared_code_d_total=$(($shared_code_d_total + $shared_value))
                    shared_parts_d+=($shared_file)
                fi
            fi

            # Total code decryption - end


            case $code_section in
                $CODE_SECTION_INI)
                    shared_code_ini=$(($shared_code_ini + $shared_value))
                    ;;
                $CODE_SECTION_PAD)
                    shared_code_pad=$(($shared_code_pad + $shared_value))
                    ;;
                $CODE_SECTION_PPD)
                    shared_code_ppd=$(($shared_code_ppd + $shared_value))
                    ;;
                $CODE_SECTION_FIN)
                    shared_code_fin=$(($shared_code_fin + $shared_value))
                    ;;
                $CODE_SECTION_TG)
                    shared_code_tg=$(($shared_code_tg + $shared_value))
                    ;;
                $CODE_SECTION_PCD)
                    shared_code_pcd=$(($shared_code_pcd + $shared_value))
                    ;;
            esac
        done
    done


    shared_constants_ini=0
    shared_constants_pad=0
    shared_constants_ppd=0
    shared_constants_fin=0
    shared_constants_tg=0
    shared_constants_pcd=0
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
            shared_name=$shared_file"_rom"

            shared_value=${!shared_name}
            if [ "" == "$shared_value" ] ; then
                shared_value=0
            fi


            # Test if the shared file ROM was added to the total
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

    # Check if finalization is used or not
    use_finalization=$(cat $IMPLEMENTATION_INFO_FILE | grep $USE_FINALIZATION$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 |  tr -d '[[:space:]]')

    # Convert to lowercase
    use_finalization=${use_finalization,,}

    if [ $USE_FINALIZATION_NO == "$use_finalization" ] ; then
        finalize_rom=0
    fi

    # Check if this cipher processes empty assciated data or plaintext
    process_empty_associated_data=$(cat $IMPLEMENTATION_INFO_FILE | grep $PROCESS_EMPTY_ASSOCIATED_DATA$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 |  tr -d '[[:space:]]')
    process_empty_message=$(cat $IMPLEMENTATION_INFO_FILE | grep $PROCESS_EMPTY_MESSAGE$SECTION_SEPARATOR | tr -d '\r' | cut -d ':' -f 2 |  tr -d '[[:space:]]')

    # Cipher
    cipher_ini=$(($initialize_rom + $shared_code_ini + $shared_constants_ini))
    cipher_pad=$(($process_associated_data_rom + $shared_code_pad + $shared_constants_pad))
    cipher_ppd=$(($process_plaintext_rom + $shared_code_ppd + $shared_constants_ppd))
    cipher_fin=$(($finalize_rom + $shared_code_fin + $shared_constants_fin))
    cipher_tg=$(($tag_generation_rom + $shared_code_tg + $shared_constants_tg))
    cipher_pcd=$(($process_ciphertext_rom + $shared_code_pcd + $shared_constants_pcd))
    cipher_tv=$(($tag_verification_rom + $cipher_tg))

    if [ $SCRIPT_SCENARIO_1 -eq $SCRIPT_SCENARIO ] && [ $PROCESS_EMPTY_ASSOCIATED_DATA_NO == "$process_empty_associated_data" ]; then
        cipher_pad=0
        process_associated_data_rom=0
    fi

    if [ $SCRIPT_SCENARIO_4 -eq $SCRIPT_SCENARIO ] && [ $PROCESS_EMPTY_ASSOCIATED_DATA_NO == "$process_empty_associated_data" ]; then
        cipher_pad=0
        process_associated_data_rom=0
    fi

    if [ $SCRIPT_SCENARIO_2 -eq $SCRIPT_SCENARIO ] && [ $PROCESS_EMPTY_MESSAGE_NO == "$process_empty_message" ]; then
        cipher_ppd=0
        process_plaintext_rom=0

        cipher_pcd=0
        process_ciphertext_rom=0
    fi

    if [ $SCRIPT_SCENARIO_5 -eq $SCRIPT_SCENARIO ] && [ $PROCESS_EMPTY_MESSAGE_NO == "$process_empty_message" ]; then
        cipher_ppd=0
        process_plaintext_rom=0

        cipher_pcd=0
        process_ciphertext_rom=0
    fi


    cipher_e_total=$(($initialize_rom + $process_associated_data_rom + $process_plaintext_rom + $finalize_rom + $tag_generation_rom + $shared_code_e_total + $shared_constants_e_total))
    cipher_d_total=$(($initialize_rom + $process_associated_data_rom + $process_ciphertext_rom + $finalize_rom + $tag_generation_rom + $tag_verification_rom + $shared_code_d_total + $shared_constants_d_total))
    cipher_total=$(($initialize_rom + $process_associated_data_rom + $process_plaintext_rom + $finalize_rom + $tag_generation_rom + $process_ciphertext_rom + $tag_verification_rom + $shared_code_total + $shared_constants_total))

fi


# Dipslay results
if [ $SCRIPT_MODE_0 -eq $SCRIPT_MODE ] ; then
    # Table footer
    printf "%0.s-" $(seq 1 $TABLE_HORIZONTAL_LINE_LENGTH) >> $SCRIPT_OUTPUT
    printf "\n" >> $SCRIPT_OUTPUT
else
    printf "%s %s %s %s %s %s %s %s %s %s" $cipher_ini $cipher_pad $cipher_ppd $cipher_fin $cipher_tg $cipher_pcd $cipher_tv $cipher_e_total $cipher_d_total $cipher_total > $SCRIPT_OUTPUT
fi


# Change current working directory
cd $current_directory
if [ $SCRIPT_MODE_0 -ne $SCRIPT_MODE ] ; then
    echo ""
fi
echo "End cipher code size - $(pwd)"

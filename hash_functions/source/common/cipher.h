/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2017 University of Luxembourg
 *
 * Written in 2017 by Virat Shejwalkar <virat.shejwalkar@uni.lu>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef CIPHER_H
#define CIPHER_H

#include <stdint.h>

#ifdef AVR /* AVR */
#include <avr/pgmspace.h>
#endif /* AVR */

/*
 *
 * Essentials for scenario-2
 *
 */
#define TRUE 1
#define FALSE 0

/*
 *
 * Definitions of TRUE and FALSE used for skip state check macros
 *
 */
#define SKIP_STATE_CHECK_TRUE 1
#define SKIP_STATE_CHECK_FALSE 0

/*
 *
 * Optimization levels
 * ... OPTIMIZATION_LEVEL_0 - O0
 * ... OPTIMIZATION_LEVEL_1 - O1
 * ... OPTIMIZATION_LEVEL_2 - O2
 * ... OPTIMIZATION_LEVEL_3 - O3 = defualt
 *
 */
#define OPTIMIZATION_LEVEL_0 __attribute__((optimize("O0")))
#define OPTIMIZATION_LEVEL_1 __attribute__((optimize("O1")))
#define OPTIMIZATION_LEVEL_2 __attribute__((optimize("O2")))
#define OPTIMIZATION_LEVEL_3 __attribute__((optimize("O3")))


/*
 * 
 * SCENARIO values:
 * ... SCENARIO_0 0 - cipher operation: encrypt & decrypt one data block
 * ... SCENARIO_1A 11 - scenario 1a: hash 16 bytes of data
 * ... SCENARIO_1B 12 - scenario 1b: hash 128 bytes of data
 * ... SCENARIO_1C 13 - scenario 1c: hash 1024 bytes of data
 *
 */
#define SCENARIO_0 0
#define SCENARIO_1A 11
#define SCENARIO_1B 12
#define SCENARIO_1C 13
#define SCENARIO_2 2

#ifndef SCENARIO
#define SCENARIO SCENARIO_0
#endif

/*
 * 
 * Scenario characteristics: 
 *		MESSAGE_SIZE - the cipher data size in bytes
 *
 */

/* Scenario 0 data */
#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)
#define MESSAGE_SIZE TEST_MESSAGE_SIZE
#endif

/* Scenario 1A data */
#if defined(SCENARIO) && (SCENARIO_1A == SCENARIO)
#define MESSAGE_SIZE 16
#endif

/* Scenario 1B data */
#if defined(SCENARIO) && (SCENARIO_1B == SCENARIO)
#define MESSAGE_SIZE 128
#endif

/* Scenario 1C data */
#if defined(SCENARIO) && (SCENARIO_1C == SCENARIO)
#define MESSAGE_SIZE 1024
#endif

/* Scenario 2 data */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
#define MESSAGE_SIZE 11
#endif

/*
 *
 * MEASURE_CYCLE_COUNT values:
 * ... MEASURE_CYCLE_COUNT_DISABLED 0 - measure cycle count is disabled
 * ... MEASURE_CYCLE_COUNT_ENABLED 1 - measure cycle count is enabled
 *
 */
#define MEASURE_CYCLE_COUNT_DISABLED 0
#define MEASURE_CYCLE_COUNT_ENABLED 1

#ifndef MEASURE_CYCLE_COUNT
#define MEASURE_CYCLE_COUNT MEASURE_CYCLE_COUNT_DISABLED
#endif


/*
 *
 * Align memory boundaries in bytes
 *
 */
#define ALIGN_PC_BOUNDRY 64
#define ALIGN_AVR_BOUNDRY 2
#define ALIGN_MSP_BOUNDRY 2
#define ALIGN_ARM_BOUNDRY 8

#if defined(PC) && !defined(ALIGNED) /* PC ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_PC_BOUNDRY)))
#endif /* PC ALIGNED */

#if defined(AVR) && !defined(ALIGNED) /* AVR ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_AVR_BOUNDRY)))
#endif /* AVR ALIGNED */

#if defined(MSP) && !defined(ALIGNED) /* MSP ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_MSP_BOUNDRY)))
#endif /* MSP ALIGNED */

#if defined(ARM) && !defined(ALIGNED) /* ARM ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_ARM_BOUNDRY)))
#endif /* ARM ALIGNED */


/* 
 *
 * RAM data types 
 *
 */
#define RAM_DATA_BYTE uint8_t ALIGNED
#define RAM_DATA_WORD uint16_t ALIGNED
#define RAM_DATA_DOUBLE_WORD uint32_t ALIGNED

#define READ_RAM_DATA_BYTE(x) x
#define READ_RAM_DATA_WORD(x) x
#define READ_RAM_DATA_DOUBLE_WORD(x) x


/* 
 *
 * Flash/ROM data types 
 *
 */
#if defined(AVR) /* AVR */
#define ROM_DATA_BYTE const uint8_t PROGMEM ALIGNED
#define ROM_DATA_WORD const uint16_t PROGMEM ALIGNED
#define ROM_DATA_DOUBLE_WORD const uint32_t PROGMEM ALIGNED

#define READ_ROM_DATA_BYTE(x) pgm_read_byte(&x)
#define READ_ROM_DATA_WORD(x) pgm_read_word(&x)
#define READ_ROM_DATA_DOUBLE_WORD(x) pgm_read_dword(&x)
#else /* AVR */
#define ROM_DATA_BYTE const uint8_t ALIGNED
#define ROM_DATA_WORD const uint16_t ALIGNED
#define ROM_DATA_DOUBLE_WORD const uint32_t ALIGNED

#define READ_ROM_DATA_BYTE(x) x
#define READ_ROM_DATA_WORD(x) x
#define READ_ROM_DATA_DOUBLE_WORD(x) x
#endif /* AVR */

/*
 *
 * Initialization of state and absorption of key and nonce
 * ... key - the cipher key
 * ... nonce - initialization vector
 * ... state - state of the cipher
 *
 */
void Initialize(uint8_t *state);


/*
 *
 * Compression of input message through absorption in the hash state
 * ... message_block - message_block after padding
 * ... state - state of the hash
 *
 */
void Update(uint8_t *state, uint8_t *messageBlock, uint16_t message_len);


/*
 *
 * Absorb key in current cipher state and generate/verify tag
 * ... state - state of the hash
 * ... digest - final digest
 *
 */
void Finalize(uint8_t *state, uint8_t *digest);


#endif /* CIPHER_H */

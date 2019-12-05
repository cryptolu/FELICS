/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 16-bit MSP430F1611, Fast speed code (C+ASM)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#ifndef DATA_TYPES_H
#define DATA_TYPES_H

#include "cipher.h"


/*
 *
 * Implementation data types
 *
 */

/* Note: the order of data in this structure is highly important! */
typedef struct GrainState_st
{	uint16_t lfsr[8], nfsr[8], A[4], R[5];
} GrainState;


#if defined(PC) /* PC */

/* Architecture = PC ; Scenario = 0 (cipher operation) */
#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

/* Architecture = PC ; Scenario = 1 */
#if defined(SCENARIO) && (SCENARIO_1 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

/* Architecture = PC ; Scenario = 2 */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

/* Architecture = PC ; Scenario = 3 */
#if defined(SCENARIO) && (SCENARIO_3 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

/* Architecture = PC ; Scenario = 4 */
#if defined(SCENARIO) && (SCENARIO_4 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

#endif /* PC */



#if defined(AVR) /* AVR */

/* Architecture = AVR ; Scenario = 0 (cipher operation) */
#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

/* Architecture = AVR ; Scenario = 1 */
#if defined(SCENARIO) && (SCENARIO_1 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

/* Architecture = AVR ; Scenario = 2 */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

/* Architecture = AVR ; Scenario = 3 */
#if defined(SCENARIO) && (SCENARIO_3 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

/* Architecture = AVR ; Scenario = 4 */
#if defined(SCENARIO) && (SCENARIO_4 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

#endif /* AVR */



#if defined(MSP) /* MSP */

/* Architecture = MSP ; Scenario = 0 (cipher operation) */
#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

/* Architecture = MSP ; Scenario = 1 */
#if defined(SCENARIO) && (SCENARIO_1 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

/* Architecture = MSP ; Scenario = 2 */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

/* Architecture = MSP ; Scenario = 3 */
#if defined(SCENARIO) && (SCENARIO_3 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

/* Architecture = MSP ; Scenario = 4 */
#if defined(SCENARIO) && (SCENARIO_4 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

#endif /* MSP */



#if defined(ARM) /* ARM */

/* Architecture = ARM ; Scenario = 0 (cipher operation) */
#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

/* Architecture = ARM ; Scenario = 1 */
#if defined(SCENARIO) && (SCENARIO_1 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

/* Architecture = ARM ; Scenario = 2 */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

/* Architecture = ARM ; Scenario = 3 */
#if defined(SCENARIO) && (SCENARIO_3 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

/* Architecture = ARM ; Scenario = 4 */
#if defined(SCENARIO) && (SCENARIO_4 == SCENARIO)

/* Replace with your custom data types and read macros for this architecture and scenario */
#define SBOX_BYTE ROM_DATA_BYTE
#define READ_SBOX_BYTE READ_ROM_DATA_BYTE

#endif

#endif /* ARM */


#endif /* DATA_TYPES_H */

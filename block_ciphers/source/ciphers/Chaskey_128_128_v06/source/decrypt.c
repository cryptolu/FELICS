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
 *                    Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

/*
 *
 * Katholieke Universiteit Leuven
 * Computer Security and Industrial Cryptography (COSIC)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 Katholieke Universiteit Leuven
 *
 * Written in 2015 by Nicky Mouha <nicky.mouha@esat.kuleuven.be>
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

/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

#include <stdint.h>

#include "cipher.h"
#include "constants.h"


#if defined(AVR)

#ifndef AVR_CLOBBERED_REGISTERS
#define AVR_CLOBBERED_REGISTERS
#endif

#include "avr_basic_asm_macros.h"

#ifndef AVR_CLOBBERED_REGISTERS
void __attribute__((naked)) Decrypt(uint8_t *block, uint8_t *roundKeys)
#else
void Decrypt(uint8_t *block, uint8_t *roundKeys)
#endif
{
    /*  
     * r4-r19: state
     * r3: key
     * r20, r21: temp registers
     */
    asm(
#ifndef AVR_CLOBBERED_REGISTERS
        /* push the registers that are being used in code */
        "push r27"                "\n\t"
        "push r26"                "\n\t"

        "push r17"               "\n\t"
        "push r16"               "\n\t"
        "push r15"               "\n\t"
        "push r14"               "\n\t"
        "push r13"               "\n\t"
        "push r12"               "\n\t"
        "push r11"               "\n\t"
        "push r10"               "\n\t"
        "push r9"                "\n\t"
        "push r8"                "\n\t"
        "push r7"                "\n\t"
        "push r6"                "\n\t"
        "push r5"                "\n\t"
        "push r4"                "\n\t"
        "push r3"                "\n\t"
#endif


        /* set block pointer: X (r27, r26) */
#ifndef AVR_CLOBBERED_REGISTERS
        "movw r26, r24"          "\n\t"
#else
        "movw r26, %[block]"          "\n\t"
#endif

        "ld r4, x+"              "\n\t"
        "ld r5, x+"              "\n\t"
        "ld r6, x+"              "\n\t"
        "ld r7, x+"              "\n\t"
        "ld r8, x+"              "\n\t"
        "ld r9, x+"              "\n\t"
        "ld r10, x+"             "\n\t"
        "ld r11, x+"             "\n\t"

        "ld r12, x+"             "\n\t"
        "ld r13, x+"             "\n\t"
        "ld r14, x+"             "\n\t"
        "ld r15, x+"             "\n\t"
        "ld r16, x+"             "\n\t"
        "ld r17, x+"             "\n\t"
        "ld r18, x+"             "\n\t"
        "ld r19, x"              "\n\t"


        /* set key pointer: Z (r31, r30) */
#ifndef AVR_CLOBBERED_REGISTERS
        "movw r30, r22"          "\n\t"
#else
        "movw r30, %[roundKeys]"          "\n\t"
#endif

        /* key whitening at the begining of decryption */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "sbiw r30, 16             \n\t"

        "lpm r3, z+"            "\n\t"
        "eor r4, r3"            "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r5, r3"            "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r6, r3"            "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r7, r3"            "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r8, r3"            "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r9, r3"            "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r10, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r11, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r12, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r13, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r14, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r15, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r16, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r17, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r18, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r19, r3"           "\n\t"
#else
        "ld r3, z+"             "\n\t"
        "eor r4, r3"            "\n\t"

        "ld r3, z+"             "\n\t"
        "eor r5, r3"            "\n\t"

        "ld r3, z+"             "\n\t"
        "eor r6, r3"            "\n\t"

        "ld r3, z+"             "\n\t"
        "eor r7, r3"            "\n\t"

        "ld r3, z+"             "\n\t"
        "eor r8, r3"            "\n\t"

        "ld r3, z+"             "\n\t"
        "eor r9, r3"            "\n\t"

        "ld r3, z+"             "\n\t"
        "eor r10, r3"           "\n\t"

        "ld r3, z+"             "\n\t"
        "eor r11, r3"           "\n\t"

        "ld r3, z+"             "\n\t"
        "eor r12, r3"           "\n\t"

        "ld r3, z+"             "\n\t"
        "eor r13, r3"           "\n\t"

        "ld r3, z+"             "\n\t"
        "eor r14, r3"           "\n\t"

        "ld r3, z+"             "\n\t"
        "eor r15, r3"           "\n\t"

        "ld r3, z+"             "\n\t"
        "eor r16, r3"           "\n\t"

        "ld r3, z+"             "\n\t"
        "eor r17, r3"           "\n\t"

        "ld r3, z+"             "\n\t"
        "eor r18, r3"           "\n\t"

        "ld r3, z"              "\n\t"
        "eor r19, r3"           "\n\t"
#endif


        CHASKEY_DEC_ROUND(r19, r18, r17, r16, r15, r14, r13, r12, r11, r10, r9, r8, r7, r6, r5, r4, r20, r21)
        CHASKEY_DEC_ROUND(r19, r18, r17, r16, r15, r14, r13, r12, r11, r10, r9, r8, r7, r6, r5, r4, r20, r21)
        CHASKEY_DEC_ROUND(r19, r18, r17, r16, r15, r14, r13, r12, r11, r10, r9, r8, r7, r6, r5, r4, r20, r21)
        CHASKEY_DEC_ROUND(r19, r18, r17, r16, r15, r14, r13, r12, r11, r10, r9, r8, r7, r6, r5, r4, r20, r21)


        CHASKEY_DEC_ROUND(r19, r18, r17, r16, r15, r14, r13, r12, r11, r10, r9, r8, r7, r6, r5, r4, r20, r21)
        CHASKEY_DEC_ROUND(r19, r18, r17, r16, r15, r14, r13, r12, r11, r10, r9, r8, r7, r6, r5, r4, r20, r21)
        CHASKEY_DEC_ROUND(r19, r18, r17, r16, r15, r14, r13, r12, r11, r10, r9, r8, r7, r6, r5, r4, r20, r21)
        CHASKEY_DEC_ROUND(r19, r18, r17, r16, r15, r14, r13, r12, r11, r10, r9, r8, r7, r6, r5, r4, r20, r21)



        /* key whitening at the end of the decryption */
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "eor r19, r3"           "\n\t"

        "sbiw r30, 15             \n\t"

        "lpm r3, z+"            "\n\t"
        "eor r4, r3"            "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r5, r3"            "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r6, r3"            "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r7, r3"            "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r8, r3"            "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r9, r3"            "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r10, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r11, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r12, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r13, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r14, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r15, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r16, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r17, r3"           "\n\t"

        "lpm r3, z+"            "\n\t"
        "eor r18, r3"           "\n\t"
#else
        "eor r19, r3"           "\n\t"
        
        "ld r3, -z"             "\n\t"
        "eor r18, r3"           "\n\t"

        "ld r3, -z"             "\n\t"
        "eor r17, r3"           "\n\t"

        "ld r3, -z"             "\n\t"
        "eor r16, r3"           "\n\t"

        "ld r3, -z"             "\n\t"
        "eor r15, r3"           "\n\t"

        "ld r3, -z"             "\n\t"
        "eor r14, r3"           "\n\t"

        "ld r3, -z"             "\n\t"
        "eor r13, r3"           "\n\t"

        "ld r3, -z"             "\n\t"
        "eor r12, r3"           "\n\t"

        "ld r3, -z"             "\n\t"
        "eor r11, r3"           "\n\t"

        "ld r3, -z"             "\n\t"
        "eor r10, r3"           "\n\t"

        "ld r3, -z"             "\n\t"
        "eor r9, r3"            "\n\t"

        "ld r3, -z"             "\n\t"
        "eor r8, r3"            "\n\t"

        "ld r3, -z"             "\n\t"
        "eor r7, r3"            "\n\t"

        "ld r3, -z"             "\n\t"
        "eor r6, r3"            "\n\t"

        "ld r3, -z"             "\n\t"
        "eor r5, r3"            "\n\t"

        "ld r3, -z"             "\n\t"
        "eor r4, r3"            "\n\t"
#endif


        /* store the ciphertext back in memory */
        "st  x, r19"             "\n\t"
        "st -x, r18"             "\n\t"
        "st -x, r17"             "\n\t"
        "st -x, r16"             "\n\t"
        "st -x, r15"             "\n\t"
        "st -x, r14"             "\n\t"
        "st -x, r13"             "\n\t"
        "st -x, r12"             "\n\t"

        "st -x, r11"             "\n\t"
        "st -x, r10"             "\n\t"
        "st -x, r9"              "\n\t"
        "st -x, r8"              "\n\t"
        "st -x, r7"              "\n\t"
        "st -x, r6"              "\n\t"
        "st -x, r5"              "\n\t"
        "st -x, r4"              "\n\t"


#ifndef AVR_CLOBBERED_REGISTERS
        /* pop the used registers */
        "pop r3"                 "\n\t"
        "pop r4"                 "\n\t"
        "pop r5"                 "\n\t"
        "pop r6"                 "\n\t"
        "pop r7"                 "\n\t"
        "pop r8"                 "\n\t"
        "pop r9"                 "\n\t"
        "pop r10"                "\n\t"
        "pop r11"                "\n\t"
        "pop r12"                "\n\t"
        "pop r13"                "\n\t"
        "pop r14"                "\n\t"
        "pop r15"                "\n\t"
        "pop r16"                "\n\t"
        "pop r17"                "\n\t"

        "pop r26"                "\n\t"
        "pop r27"                "\n\t"


        "ret"                    "\n\t"
#endif


#ifdef AVR_CLOBBERED_REGISTERS
        :
        : [block] "r" (block), [roundKeys] "r" (roundKeys)
        : "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r26", "r27", "r30", "r31"
#endif
    );
}

#elif defined(MSP)

#ifndef MSP_CLOBBERED_REGISTERS
#define MSP_CLOBBERED_REGISTERS
#endif

#include "msp430_basic_asm_macros.h"

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
    /*
     * r15: *block
     * r14: *roundKeys
     * r5 - r12: state
     * r13: key / tmp
     */
    asm volatile(
#ifndef MSP_CLOBBERED_REGISTERS
        /* push the registers that are being used in code */
        "push r5"                               "\n\t"
        "push r6"                               "\n\t"
        "push r7"                               "\n\t"
        "push r8"                               "\n\t"
        "push r9"                               "\n\t"
        "push r10"                              "\n\t"
        "push r11"                              "\n\t"
#endif


        /* load plaintext bytes from memory */
#ifndef MSP_CLOBBERED_REGISTERS
        "mov @r15+, r5"                         "\n\t"
        "mov @r15+, r6"                         "\n\t"
        "mov @r15+, r7"                         "\n\t"
        "mov @r15+, r8"                         "\n\t"
        "mov @r15+, r9"                         "\n\t"
        "mov @r15+, r10"                        "\n\t"
        "mov @r15+, r11"                        "\n\t"
        "mov @r15+, r12"                        "\n\t"
#else
        "mov @%[block]+, r5"                    "\n\t"
        "mov @%[block]+, r6"                    "\n\t"
        "mov @%[block]+, r7"                    "\n\t"
        "mov @%[block]+, r8"                    "\n\t"
        "mov @%[block]+, r9"                    "\n\t"
        "mov @%[block]+, r10"                   "\n\t"
        "mov @%[block]+, r11"                   "\n\t"
        "mov @%[block]+, r12"                   "\n\t"
#endif


        /* key whitening at the begining of decryption */
#ifndef MSP_CLOBBERED_REGISTERS
        "mov @r14+, r13"                        "\n\t"
        "xor r13, r5"                           "\n\t"

        "mov @r14+, r13"                        "\n\t"
        "xor r13, r6"                           "\n\t"

        "mov @r14+, r13"                        "\n\t"
        "xor r13, r7"                           "\n\t"

        "mov @r14+, r13"                        "\n\t"
        "xor r13, r8"                           "\n\t"

        "mov @r14+, r13"                        "\n\t"
        "xor r13, r9"                           "\n\t"

        "mov @r14+, r13"                        "\n\t"
        "xor r13, r10"                          "\n\t"

        "mov @r14+, r13"                        "\n\t"
        "xor r13, r11"                          "\n\t"

        "mov @r14+, r13"                        "\n\t"
        "xor r13, r12"                          "\n\t"
#else
        "mov @%[roundKeys]+, r13"               "\n\t"
        "xor r13, r5"                           "\n\t"

        "mov @%[roundKeys]+, r13"               "\n\t"
        "xor r13, r6"                           "\n\t"

        "mov @%[roundKeys]+, r13"               "\n\t"
        "xor r13, r7"                           "\n\t"

        "mov @%[roundKeys]+, r13"               "\n\t"
        "xor r13, r8"                           "\n\t"

        "mov @%[roundKeys]+, r13"               "\n\t"
        "xor r13, r9"                           "\n\t"

        "mov @%[roundKeys]+, r13"               "\n\t"
        "xor r13, r10"                          "\n\t"

        "mov @%[roundKeys]+, r13"               "\n\t"
        "xor r13, r11"                          "\n\t"

        "mov @%[roundKeys]+, r13"               "\n\t"
        "xor r13, r12"                          "\n\t"
#endif


        CHASKEY_DEC_ROUND(r12, r11, r10, r9, r8, r7, r6, r5, r13)
        CHASKEY_DEC_ROUND(r12, r11, r10, r9, r8, r7, r6, r5, r13)
        CHASKEY_DEC_ROUND(r12, r11, r10, r9, r8, r7, r6, r5, r13)
        CHASKEY_DEC_ROUND(r12, r11, r10, r9, r8, r7, r6, r5, r13)

        CHASKEY_DEC_ROUND(r12, r11, r10, r9, r8, r7, r6, r5, r13)
        CHASKEY_DEC_ROUND(r12, r11, r10, r9, r8, r7, r6, r5, r13)
        CHASKEY_DEC_ROUND(r12, r11, r10, r9, r8, r7, r6, r5, r13)
        CHASKEY_DEC_ROUND(r12, r11, r10, r9, r8, r7, r6, r5, r13)


        /* key whitening at the end of the decryption */
#ifndef MSP_CLOBBERED_REGISTERS
        "mov -16(r14), r13"                     "\n\t"
        "xor r13, r5"                           "\n\t"

        "mov -14(r14), r13"                     "\n\t"
        "xor r13, r6"                           "\n\t"

        "mov -12(r14), r13"                     "\n\t"
        "xor r13, r7"                           "\n\t"

        "mov -10(r14), r13"                     "\n\t"
        "xor r13, r8"                           "\n\t"

        "mov -8(r14), r13"                      "\n\t"
        "xor r13, r9"                           "\n\t"

        "mov -6(r14), r13"                      "\n\t"
        "xor r13, r10"                          "\n\t"

        "mov -4(r14), r13"                      "\n\t"
        "xor r13, r11"                          "\n\t"

        "mov -2(r14), r13"                      "\n\t"
        "xor r13, r12"                          "\n\t"
#else
        "mov -16(%[roundKeys]), r13"            "\n\t"
        "xor r13, r5"                           "\n\t"

        "mov -14(%[roundKeys]), r13"            "\n\t"
        "xor r13, r6"                           "\n\t"

        "mov -12(%[roundKeys]), r13"            "\n\t"
        "xor r13, r7"                           "\n\t"

        "mov -10(%[roundKeys]), r13"            "\n\t"
        "xor r13, r8"                           "\n\t"

        "mov -8(%[roundKeys]), r13"             "\n\t"
        "xor r13, r9"                           "\n\t"

        "mov -6(%[roundKeys]), r13"             "\n\t"
        "xor r13, r10"                          "\n\t"

        "mov -4(%[roundKeys]), r13"             "\n\t"
        "xor r13, r11"                          "\n\t"

        "mov -2(%[roundKeys]), r13"             "\n\t"
        "xor r13, r12"                          "\n\t"
#endif


        /* store the ciphertext back in memory */
#ifndef MSP_CLOBBERED_REGISTERS
        "mov r5, -16(r15)"                      "\n\t"
        "mov r6, -14(r15)"                      "\n\t"
        "mov r7, -12(r15)"                      "\n\t"
        "mov r8, -10(r15)"                      "\n\t"
        "mov r9, -8(r15)"                       "\n\t"
        "mov r10, -6(r15)"                      "\n\t"
        "mov r11, -4(r15)"                      "\n\t"
        "mov r12, -2(r15)"                      "\n\t"
#else
        "mov r5, -16(%[block])"                 "\n\t"
        "mov r6, -14(%[block])"                 "\n\t"
        "mov r7, -12(%[block])"                 "\n\t"
        "mov r8, -10(%[block])"                 "\n\t"
        "mov r9, -8(%[block])"                  "\n\t"
        "mov r10, -6(%[block])"                 "\n\t"
        "mov r11, -4(%[block])"                 "\n\t"
        "mov r12, -2(%[block])"                 "\n\t"
#endif


#ifndef MSP_CLOBBERED_REGISTERS
        /* pop the used registers */
        "pop r11"                               "\n\t"
        "pop r10"                               "\n\t"
        "pop r9"                                "\n\t"
        "pop r8"                                "\n\t"
        "pop r7"                                "\n\t"
        "pop r6"                                "\n\t"
        "pop r5"                                "\n\t"
#endif


#ifdef MSP_CLOBBERED_REGISTERS
        : 
        : [block] "r" (block), [roundKeys] "r" (roundKeys)
        : "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13"
#endif
    );
}

#elif defined(ARM)

#ifndef ARM_CLOBBERED_REGISTERS
#define ARM_CLOBBERED_REGISTERS
#endif

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
    /*
     * r0: *block
     * r1: *roundKeys
     * r2 - r5: state
     * r6: key
     */
    asm volatile(
#ifndef ARM_CLOBBERED_REGISTERS
        /* push the necessary registers on stack */
        "stmdb sp!, {r2-r6}"                      "\n\t"
#endif


        /* load state in r2 - r5 */
#ifndef ARM_CLOBBERED_REGISTERS
        "ldm r0, {r2-r5}"                         "\n\t"
#else
        "ldm %[block], {r2-r5}"                   "\n\t"
#endif


        /* key whitening */
#ifndef ARM_CLOBBERED_REGISTERS
        "ldm r1!, {r6}"                           "\n\t"
        "eor r2, r6, r2"                          "\n\t"

        "ldm r1!, {r6}"                           "\n\t"
        "eor r3, r6, r3"                          "\n\t"

        "ldm r1!, {r6}"                           "\n\t"
        "eor r4, r6, r4"                          "\n\t"

        "ldm r1!, {r6}"                           "\n\t"
        "eor r5, r6, r5"                          "\n\t"
#else
        "ldm %[roundKeys]!, {r6}"                 "\n\t"
        "eor r2, r6, r2"                          "\n\t"

        "ldm %[roundKeys]!, {r6}"                 "\n\t"
        "eor r3, r6, r3"                          "\n\t"

        "ldm %[roundKeys]!, {r6}"                 "\n\t"
        "eor r4, r6, r4"                          "\n\t"

        "ldm %[roundKeys]!, {r6}"                 "\n\t"
        "eor r5, r6, r5"                          "\n\t"
#endif


        /* decryption round 1 - begin */
        "ror r4, r4, #16"                         "\n\t"
        "eor r3, r3, r4"                          "\n\t"
        "ror r3, r3, #7"                          "\n\t"
        "sub r4, r4, r3"                          "\n\t"

        "eor r5, r5, r2"                          "\n\t"
        "ror r5, r5, #13"                         "\n\t"
        "sub r2, r2, r5"                          "\n\t"

        "eor r5, r5, r4"                          "\n\t"
        "ror r5, r5, #8"                          "\n\t"
        "sub r4, r4, r5"                          "\n\t"
        
        "ror r2, r2, #16"                         "\n\t"
        "eor r3, r2, r3"                          "\n\t"
        "ror r3, r3, #5"                          "\n\t"
        "sub r2, r2, r3"                          "\n\t"
        /* decryption round 1 - end */


        /* decryption round 2 - begin */
        "ror r4, r4, #16"                         "\n\t"
        "eor r3, r3, r4"                          "\n\t"
        "ror r3, r3, #7"                          "\n\t"
        "sub r4, r4, r3"                          "\n\t"

        "eor r5, r5, r2"                          "\n\t"
        "ror r5, r5, #13"                         "\n\t"
        "sub r2, r2, r5"                          "\n\t"

        "eor r5, r5, r4"                          "\n\t"
        "ror r5, r5, #8"                          "\n\t"
        "sub r4, r4, r5"                          "\n\t"
        
        "ror r2, r2, #16"                         "\n\t"
        "eor r3, r2, r3"                          "\n\t"
        "ror r3, r3, #5"                          "\n\t"
        "sub r2, r2, r3"                          "\n\t"
        /* decryption round 2 - end */


        /* decryption round 3 - begin */
        "ror r4, r4, #16"                         "\n\t"
        "eor r3, r3, r4"                          "\n\t"
        "ror r3, r3, #7"                          "\n\t"
        "sub r4, r4, r3"                          "\n\t"

        "eor r5, r5, r2"                          "\n\t"
        "ror r5, r5, #13"                         "\n\t"
        "sub r2, r2, r5"                          "\n\t"

        "eor r5, r5, r4"                          "\n\t"
        "ror r5, r5, #8"                          "\n\t"
        "sub r4, r4, r5"                          "\n\t"
        
        "ror r2, r2, #16"                         "\n\t"
        "eor r3, r2, r3"                          "\n\t"
        "ror r3, r3, #5"                          "\n\t"
        "sub r2, r2, r3"                          "\n\t"
        /* decryption round 3 - end */


        /* decryption round 4 - begin */
        "ror r4, r4, #16"                         "\n\t"
        "eor r3, r3, r4"                          "\n\t"
        "ror r3, r3, #7"                          "\n\t"
        "sub r4, r4, r3"                          "\n\t"

        "eor r5, r5, r2"                          "\n\t"
        "ror r5, r5, #13"                         "\n\t"
        "sub r2, r2, r5"                          "\n\t"

        "eor r5, r5, r4"                          "\n\t"
        "ror r5, r5, #8"                          "\n\t"
        "sub r4, r4, r5"                          "\n\t"
        
        "ror r2, r2, #16"                         "\n\t"
        "eor r3, r2, r3"                          "\n\t"
        "ror r3, r3, #5"                          "\n\t"
        "sub r2, r2, r3"                          "\n\t"
        /* decryption round 4 - end */


        /* decryption round 5 - begin */
        "ror r4, r4, #16"                         "\n\t"
        "eor r3, r3, r4"                          "\n\t"
        "ror r3, r3, #7"                          "\n\t"
        "sub r4, r4, r3"                          "\n\t"

        "eor r5, r5, r2"                          "\n\t"
        "ror r5, r5, #13"                         "\n\t"
        "sub r2, r2, r5"                          "\n\t"

        "eor r5, r5, r4"                          "\n\t"
        "ror r5, r5, #8"                          "\n\t"
        "sub r4, r4, r5"                          "\n\t"
        
        "ror r2, r2, #16"                         "\n\t"
        "eor r3, r2, r3"                          "\n\t"
        "ror r3, r3, #5"                          "\n\t"
        "sub r2, r2, r3"                          "\n\t"
        /* decryption round 5 - end */


        /* decryption round 6 - begin */
        "ror r4, r4, #16"                         "\n\t"
        "eor r3, r3, r4"                          "\n\t"
        "ror r3, r3, #7"                          "\n\t"
        "sub r4, r4, r3"                          "\n\t"

        "eor r5, r5, r2"                          "\n\t"
        "ror r5, r5, #13"                         "\n\t"
        "sub r2, r2, r5"                          "\n\t"

        "eor r5, r5, r4"                          "\n\t"
        "ror r5, r5, #8"                          "\n\t"
        "sub r4, r4, r5"                          "\n\t"
        
        "ror r2, r2, #16"                         "\n\t"
        "eor r3, r2, r3"                          "\n\t"
        "ror r3, r3, #5"                          "\n\t"
        "sub r2, r2, r3"                          "\n\t"
        /* decryption round 6 - end */


        /* decryption round 7 - begin */
        "ror r4, r4, #16"                         "\n\t"
        "eor r3, r3, r4"                          "\n\t"
        "ror r3, r3, #7"                          "\n\t"
        "sub r4, r4, r3"                          "\n\t"

        "eor r5, r5, r2"                          "\n\t"
        "ror r5, r5, #13"                         "\n\t"
        "sub r2, r2, r5"                          "\n\t"

        "eor r5, r5, r4"                          "\n\t"
        "ror r5, r5, #8"                          "\n\t"
        "sub r4, r4, r5"                          "\n\t"
        
        "ror r2, r2, #16"                         "\n\t"
        "eor r3, r2, r3"                          "\n\t"
        "ror r3, r3, #5"                          "\n\t"
        "sub r2, r2, r3"                          "\n\t"
        /* decryption round 7 - end */


        /* decryption round 8 - begin */
        "ror r4, r4, #16"                         "\n\t"
        "eor r3, r3, r4"                          "\n\t"
        "ror r3, r3, #7"                          "\n\t"
        "sub r4, r4, r3"                          "\n\t"

        "eor r5, r5, r2"                          "\n\t"
        "ror r5, r5, #13"                         "\n\t"
        "sub r2, r2, r5"                          "\n\t"

        "eor r5, r5, r4"                          "\n\t"
        "ror r5, r5, #8"                          "\n\t"
        "sub r4, r4, r5"                          "\n\t"
        
        "ror r2, r2, #16"                         "\n\t"
        "eor r3, r2, r3"                          "\n\t"
        "ror r3, r3, #5"                          "\n\t"
        "sub r2, r2, r3"                          "\n\t"
        /* decryption round 8 - end */


        /* key whitening */
#ifndef ARM_CLOBBERED_REGISTERS
        "ldmdb r1!, {r6}"                         "\n\t"
        "eor r5, r6, r5"                          "\n\t"

        "ldmdb r1!, {r6}"                         "\n\t"
        "eor r4, r6, r4"                          "\n\t"

        "ldmdb r1!, {r6}"                         "\n\t"
        "eor r3, r6, r3"                          "\n\t"

        "ldmdb r1!, {r6}"                         "\n\t"
        "eor r2, r6, r2"                          "\n\t"
#else
        "ldmdb %[roundKeys]!, {r6}"               "\n\t"
        "eor r5, r6, r5"                          "\n\t"

        "ldmdb %[roundKeys]!, {r6}"              "\n\t"
        "eor r4, r6, r4"                          "\n\t"

        "ldmdb %[roundKeys]!, {r6}"               "\n\t"
        "eor r3, r6, r3"                          "\n\t"

        "ldmdb %[roundKeys]!, {r6}"               "\n\t"
        "eor r2, r6, r2"                          "\n\t"
#endif


        /* store state from r2 - r5 */
#ifndef ARM_CLOBBERED_REGISTERS
        "stm r0, {r2-r5}"                         "\n\t"
#else
        "stm %[block], {r2-r5}"                   "\n\t"
#endif


#ifndef ARM_CLOBBERED_REGISTERS
        /*pop the content */
        "ldmia sp!, {r2-r6}"                      "\n\t"
#endif


#ifdef ARM_CLOBBERED_REGISTERS
        : 
        : [block] "r" (block), [roundKeys] "r" (roundKeys)
        : "r2", "r3", "r4", "r5", "r6"
#endif
    );
}

#else

#include "primitives.h"

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
  uint32_t *v = (uint32_t *)block;
  uint32_t *k = (uint32_t *)roundKeys;
  uint8_t i;

  /* Whitening */
  v[0] ^= READ_ROUND_KEY_DOUBLE_WORD(k[0]); 
  v[1] ^= READ_ROUND_KEY_DOUBLE_WORD(k[1]); 
  v[2] ^= READ_ROUND_KEY_DOUBLE_WORD(k[2]); 
  v[3] ^= READ_ROUND_KEY_DOUBLE_WORD(k[3]);

  /* Chaskey permutation */
  for (i = 0; i < NUMBER_OF_ROUNDS; ++i)
  {
    v[2]=ror(v[2],16); v[1] ^= v[2]; v[1]=ror(v[1], 7); v[2] -= v[1];
                       v[3] ^= v[0]; v[3]=ror(v[3],13); v[0] -= v[3];
                       v[3] ^= v[2]; v[3]=ror(v[3], 8); v[2] -= v[3];
    v[0]=ror(v[0],16); v[1] ^= v[0]; v[1]=ror(v[1], 5); v[0] -= v[1];
  }

  /* Whitening */
  v[0] ^= READ_ROUND_KEY_DOUBLE_WORD(k[0]); 
  v[1] ^= READ_ROUND_KEY_DOUBLE_WORD(k[1]); 
  v[2] ^= READ_ROUND_KEY_DOUBLE_WORD(k[2]); 
  v[3] ^= READ_ROUND_KEY_DOUBLE_WORD(k[3]);
}

#endif

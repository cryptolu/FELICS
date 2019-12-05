/*
 * SKINNY-64-128
 * @Time 2017
 * @Author luopeng(luopeng@iie.ac.cn)
 * 
 * Modified by luopeng, Aug 2018.
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

#ifdef AVR
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    /*--------------------------------------*/
    /* r14-r21  : plain text                */
    /* r22-r23  : temp use                  */
    /* r24      : loop control              */
    /* r25      : const 0x02                */
    /* r26-r27  : X points to plain text    */
    /* r28-r29  : Y points to roundKeys     */
    /* r30-r31  : Z points to SBOX          */
    /* -------------------------------------*/
    asm volatile(
    /*
     * http://www.atmel.com/webdoc/AVRLibcReferenceManual/FAQ_1faq_reg_usage.html
     * 
     * GCC AVR passes arguments from left to right in r25-r8.
     * All arguments are aligned to start in even-numbered registers. 
     * Pointers are 16-bits, so arguments are in r25:r24 and r23:22
     * 
     * [r18-r27, r30-r31]: You may use them freely in assembler subroutines.
     *     The caller is responsible for saving and restoring.
     * [r2-r17, r28-r29]: Calling C subroutines leaves them unchanged.
     *     Assembler subroutines are responsible for saving and restoring these registers.
     * [r0, r1]: Fixed registers. Never allocated by gcc for local data.
     */
        "push        r14        \n\t"
        "push        r15        \n\t"
        "push        r16        \n\t"
        "push        r17        \n\t"
        "push        r28        \n\t"
        "push        r29        \n\t"
        "movw        r28,         r22       \n\t"
        // Load plain text
        "ld          r20,         x+        \n\t"
        "ld          r21,         x+        \n\t"
        "ld          r14,         x+        \n\t"
        "ld          r15,         x+        \n\t"
        "ld          r16,         x+        \n\t"
        "ld          r17,         x+        \n\t"
        "ld          r19,         x+        \n\t"
        "ld          r18,         x         \n\t"
        // set currentRound
        "ldi         r24,         36        \n\t"
        // used for constant 0x02
        "ldi         r25,         0x20      \n\t"
        "ldi         r31,         hi8(SBOX) \n\t"
        // encryption
    "enc_loop:                              \n\t"
        // SubCells and the shift in MixColumns of last round
        #if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "ldi         r31,         hi8(SBOX) \n\t"
        #endif
        "movw        r22,         r20       \n\t"
        "mov         r30,         r19       \n\t"
        "lpm         r20,         z         \n\t"
        "mov         r30,         r18       \n\t"
        "lpm         r21,         z         \n\t"
        "mov         r30,         r16       \n\t"
        "lpm         r18,         z         \n\t"
        "mov         r30,         r17       \n\t"
        "lpm         r19,         z         \n\t"
        "mov         r30,         r14       \n\t"
        "lpm         r16,         z         \n\t"
        "mov         r30,         r15       \n\t"
        "lpm         r17,         z         \n\t"
        "mov         r30,         r22       \n\t"
        "lpm         r14,         z         \n\t"
        "mov         r30,         r23       \n\t"
        "lpm         r15,         z         \n\t"
        // AddRoundConstant and AddRoundKeys
        #if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "movw        r30,         r28       \n\t"
        "lpm         r22,         z+        \n\t"
        "eor         r14,         r22       \n\t"
        "lpm         r22,         z+        \n\t"
        "eor         r15,         r22       \n\t"
        "lpm         r22,         z+        \n\t"
        "eor         r16,         r22       \n\t"
        "lpm         r22,         z+        \n\t"
        "eor         r17,         r22       \n\t"
        "eor         r18,         r25       \n\t"
        "movw        r28,         r30       \n\t"
        #else
        "ld          r22,         y+        \n\t"
        "eor         r14,         r22       \n\t"
        "ld          r22,         y+        \n\t"
        "eor         r15,         r22       \n\t"
        "ld          r22,         y+        \n\t"
        "eor         r16,         r22       \n\t"
        "ld          r22,         y+        \n\t"
        "eor         r17,         r22       \n\t"
        "eor         r18,         r25       \n\t"
        #endif
        // ShiftRow, but the third line is unchanged
        "swap        r16                    \n\t"
        "swap        r17                    \n\t"
        "mov         r22,         r16       \n\t"
        "eor         r22,         r17       \n\t"
        "andi        r22,         0xf0      \n\t"
        "eor         r16,         r22       \n\t"
        "eor         r17,         r22       \n\t"
        "swap        r20                    \n\t"
        "swap        r21                    \n\t"
        "mov         r22,         r20       \n\t"
        "eor         r22,         r21       \n\t"
        "andi        r22,         0x0f      \n\t"
        "eor         r20,         r22       \n\t"
        "eor         r21,         r22       \n\t"
        // MixColumn
        "eor         r16,         r19       \n\t"
        "eor         r19,         r14       \n\t"
        "eor         r20,         r19       \n\t"
        "eor         r17,         r18       \n\t"
        "eor         r18,         r15       \n\t"
        "eor         r21,         r18       \n\t"
    "dec             r24                    \n\t"
    "brne            enc_loop               \n\t"
        // Store cipher text
        "st          x,           r18       \n\t"
        "st          -x,          r19       \n\t"
        "st          -x,          r17       \n\t"
        "st          -x,          r16       \n\t"
        "st          -x,          r15       \n\t"
        "st          -x,          r14       \n\t"
        "st          -x,          r21       \n\t"
        "st          -x,          r20       \n\t"
        "pop         r29        \n\t"
        "pop         r28        \n\t"
        "pop         r17        \n\t"
        "pop         r16        \n\t"
        "pop         r15        \n\t"
        "pop         r14        \n\t"
    :
    : [block] "x" (block), [roundKeys] "" (roundKeys), [SBOX] "" (SBOX));
}

#elif defined MSP
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    /* r4-r7   : cipher state                */
    /* r10-r12 : temp use                    */
    /* r13     : currentRound                */
    /* r14     : point to round keys         */
    /* r15     : point to block              */
    asm volatile(
        "push        r4         \n\t"
        "push        r5         \n\t"
        "push        r6         \n\t"
        "push        r7         \n\t"
        "push        r10        \n\t"
        "push        r11        \n\t"
        "mov         #36,       r13          \n\t"
        "mov         0(r15),    r4           \n\t"
        "mov         2(r15),    r5           \n\t"
        "mov         4(r15),    r6           \n\t"
        "mov         6(r15),    r7           \n\t"
    "enc_loop:                               \n\t"
        // SubColumn, AddConstant, AddRoundKeys
        "mov.b       r4,        r12          \n\t" 
        "mov.b       SBOX(r12), r11          \n\t"
        "swpb        r4                      \n\t"
        "mov.b       r4,        r12          \n\t"
        "mov.b       SBOX(r12), r10          \n\t"
        "swpb        r10                     \n\t"
        "xor         r11,       r10          \n\t"
        "xor         @r14+,     r10          \n\t"
        "mov.b       r7,        r12          \n\t" // first line
        "mov.b       SBOX(r12), r11          \n\t"
        "swpb        r7                      \n\t"
        "mov.b       r7,        r12          \n\t"
        "mov.b       SBOX(r12), r4           \n\t"
        "swpb        r4                      \n\t"
        "xor         r11,       r4           \n\t"
        "mov.b       r6,        r12          \n\t" // fourth line
        "mov.b       SBOX(r12), r11          \n\t"
        "swpb        r6                      \n\t"
        "mov.b       r6,        r12          \n\t"
        "mov.b       SBOX(r12), r7           \n\t"
        "swpb        r7                      \n\t"
        "xor         r11,       r7           \n\t"
        "xor         #0x20,     r7           \n\t"
        "mov.b       r5,        r12          \n\t" // third line
        "mov.b       SBOX(r12), r11          \n\t"
        "swpb        r5                      \n\t"
        "mov.b       r5,        r12          \n\t"
        "mov.b       SBOX(r12), r6           \n\t"
        "swpb        r6                      \n\t"
        "xor         r11,       r6           \n\t"
        "xor         @r14+,     r6           \n\t"
        "mov         r10,       r5           \n\t" // second line 
        // ShiftRow
        "bit         #1,        r6           \n\t"
        "rrc         r6                      \n\t"
        "bit         #1,        r6           \n\t"
        "rrc         r6                      \n\t"
        "bit         #1,        r6           \n\t"
        "rrc         r6                      \n\t"
        "bit         #1,        r6           \n\t"
        "rrc         r6                      \n\t"
        "swpb        r7                      \n\t"
        "rla         r4                      \n\t"
        "adc         r4                      \n\t"
        "rla         r4                      \n\t"
        "adc         r4                      \n\t"
        "rla         r4                      \n\t"
        "adc         r4                      \n\t"
        "rla         r4                      \n\t"
        "adc         r4                      \n\t"
        // MixColumn
        "xor         r7,        r6           \n\t"
        "xor         r5,        r7           \n\t"
        "xor         r7,        r4           \n\t"
    "dec             r13                     \n\t"
    "jne             enc_loop                \n\t"
        "mov         r4,        0(r15)       \n\t"
        "mov         r5,        2(r15)       \n\t"
        "mov         r6,        4(r15)       \n\t"
        "mov         r7,        6(r15)       \n\t"
        "pop         r11        \n\t"
        "pop         r10        \n\t"
        "pop         r7         \n\t"
        "pop         r6         \n\t"
        "pop         r5         \n\t"
        "pop         r4         \n\t"
    :
    : [block] "m" (block), [roundKeys] "m" (roundKeys), [SBOX] "" (SBOX));
}

#elif defined ARM
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    // r0    : ponits to plaintext
    // r1    : points to roundKeys
    // r2-r5 : cipher state
    // r6-r7 : temp use
    // r8    : loop control
    // r9    : points to SBOX
    // r10   : 0xff
    asm volatile(
        "stmdb      sp!,      {r2-r10}         \n\t"
        "mov        r8,       #36              \n\t"
        "ldr        r9,       =SBOX            \n\t"
        "mov        r10,      #0xff            \n\t"
        "ldrd       r2, r4,   [r0, #0]         \n\t"
        "mov        r3,       r2, lsr #16      \n\t"
        "mov        r5,       r4, lsr #16      \n\t"
    "enc_loop:                                 \n\t"
        // SubColumn
        // r2 (--  --  --  --  s2  s3  s0  s1)
        // r3 (--  --  --  --  s6  s7  s4  s5)
        // r4 (--  --  --  --  s10 s11 s8  s9)
        // r5 (--  --  --  --  s14 s15 s12 s13)
        "and        r6,       r2, #0xff        \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r2,r6,    #0, #8           \n\t"
        "and        r6,       r10, r2, lsr #8  \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r2,r6,    #8, #8           \n\t"
        "and        r6,       r3, #0xff        \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r3,r6,    #0, #8           \n\t"
        "and        r6,       r10, r3, lsr #8  \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r3,r6,    #8, #8           \n\t"
        "and        r6,       r4, #0xff        \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r4,r6,    #0, #8           \n\t"
        "and        r6,       r10, r4, lsr #8  \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r4,r6,    #8, #8           \n\t"
        "and        r6,       r5, #0xff        \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r5,r6,    #0, #8           \n\t"
        "and        r6,       r10, r5, lsr #8  \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r5,r6,    #8, #8           \n\t"
        // AddRoundKey and AddRoundConst
        "ldmia      r1!,      {r6}             \n\t"
        "eors       r2,       r2, r6           \n\t"
        "eors       r3,       r3, r6, lsr #16  \n\t"
        "eors       r4,       r4, #0x20        \n\t"
        // ShiftRow
        "mov        r6,       r2               \n\t"
        "bfi        r5,r5,    #16, #12         \n\t"
        "mov        r2,       r5, lsr #12      \n\t"
        "rev16      r5,       r4               \n\t"
        "bfi        r3,r3,    #16, #4          \n\t"
        "mov        r4,       r3, lsr #4       \n\t"
        "mov        r3,       r6               \n\t"
        // MixColumn
        "eors       r4,       r4, r5           \n\t"
        "eors       r5,       r5, r3           \n\t"
        "eors       r2,       r2, r5           \n\t"
    "subs           r8,       r8, #1           \n\t"
    "bne            enc_loop                   \n\t"
        "bfi        r2, r3,   #16, #16         \n\t"
        "bfi        r4, r5,   #16, #16         \n\t"
        "strd       r2, r4,   [r0, #0]         \n\t"
        "ldmia      sp!,      {r2-r10}         \n\t"
    :
    : [block] "r" (block), [roundKeys] "r" (roundKeys), [SBOX] "" (SBOX));
}

#else
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    /* Add here the cipher encryption implementation */
}

#endif

/*
 * SKINNY-128-128
 * @Time 2016
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
    /* r6-r7    : temp use                  */
    /* r8-r23   : plain text                */
    /* r24      : loop control              */
    /* r25      : const 0x02                */
    /* r26-r27  : X points to plain text    */
    /* r28-r29  : Y points to roundKeys     */
    /* r30-r31  : Z points to roundKeys in 
                  scenario2 and SBOX        */
    /* -------------------------------------*/
    // s0  s1  s2  s3       r8  r9  r10 r11
    // s4  s5  s6  s7   =   r12 r13 r14 r15
    // s8  s9  s10 s11  =   r16 r17 r18 r19
    // s12 s13 s14 s15      r20 r21 r22 r23
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
        "push        r6         \n\t"
        "push        r7         \n\t"
        "push        r8         \n\t"
        "push        r9         \n\t"
        "push        r10        \n\t"
        "push        r11        \n\t"
        "push        r12        \n\t"
        "push        r13        \n\t"
        "push        r14        \n\t"
        "push        r15        \n\t"
        "push        r16        \n\t"
        "push        r17        \n\t"
        "push        r28        \n\t"
        "push        r29        \n\t"
        "movw        r28, r22   \n\t"
        // load plain text
        // The registers are not in order. This is just to keep
        // pace with the result of MixColumn.
        //               s13 s14 s15 s12      r21 r22 r23 r20
        //               s0  s1  s2  s3   =   r8  r9  r10 r11
        // Cipher State: s7  s4  s5  s6   =   r15 r12 r13 r14
        //               s10 s11 s8  s9       r18 r19 r16 r17
        "ld          r21,         x+        \n\t"
        "ld          r22,         x+        \n\t"
        "ld          r23,         x+        \n\t"
        "ld          r20,         x+        \n\t"
        "ld          r8,          x+        \n\t"
        "ld          r9,          x+        \n\t"
        "ld          r10,         x+        \n\t"
        "ld          r11,         x+        \n\t"
        "ld          r15,         x+        \n\t"
        "ld          r12,         x+        \n\t"
        "ld          r13,         x+        \n\t"
        "ld          r14,         x+        \n\t"
        "ld          r18,         x+        \n\t"
        "ld          r19,         x+        \n\t"
        "ld          r16,         x+        \n\t"
        "ld          r17,         x         \n\t"
        // set currentRound
        "ldi         r24,         40        \n\t"
        // used for constant 0x02
        "ldi         r25,         0x02      \n\t"
        "ldi         r31,         hi8(SBOX) \n\t"
        // encryption
    "enc_loop:                              \n\t"
        // SubColumn with ShiftRow
        //               s13 s14 s15 s12      r21 r22 r23 r20
        //               s0  s1  s2  s3   =   r8  r9  r10 r11
        // Cipher State: s7  s4  s5  s6   =   r15 r12 r13 r14
        //               s10 s11 s8  s9       r18 r19 r16 r17
        // s0'  = SBOX[s13]  s1'  = SBOX[s14]  s2'  = SBOX[s15]  s3'  = SBOX[s12]
        // s4'  = SBOX[s0]   s5'  = SBOX[s1]   s6'  = SBOX[s2]   s6'  = SBOX[s3]
        // s8'  = SBOX[s7]   s9'  = SBOX[s4]   s10' = SBOX[s5]   s11' = SBOX[s6]
        // s12' = SBOX[s10]  s13' = SBOX[s11]  s14' = SBOX[s8]   s15' = SBOX[s9]
        #if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "ldi         r31,         hi8(SBOX) \n\t"
        #endif
        "movw        r6,          r8        \n\t"
        "mov         r30,         r21       \n\t"
        "lpm         r8,          z         \n\t"
        "mov         r30,         r19       \n\t"
        "lpm         r21,         z         \n\t"
        "mov         r30,         r14       \n\t"
        "lpm         r19,         z         \n\t"
        "mov         r30,         r10       \n\t"
        "lpm         r14,         z         \n\t"
        "mov         r30,         r23       \n\t"
        "lpm         r10,         z         \n\t"
        "mov         r30,         r17       \n\t"
        "lpm         r23,         z         \n\t"
        "mov         r30,         r12       \n\t"
        "lpm         r17,         z         \n\t"
        "mov         r30,         r6        \n\t"
        "lpm         r12,         z         \n\t"
        // second part
        "mov         r30,         r22       \n\t"
        "lpm         r9,          z         \n\t"
        "mov         r30,         r16       \n\t"
        "lpm         r22,         z         \n\t"
        "mov         r30,         r15       \n\t"
        "lpm         r16,         z         \n\t"
        "mov         r30,         r11       \n\t"
        "lpm         r15,         z         \n\t"
        "mov         r30,         r20       \n\t"
        "lpm         r11,         z         \n\t"
        "mov         r30,         r18       \n\t"
        "lpm         r20,         z         \n\t"
        "mov         r30,         r13       \n\t"
        "lpm         r18,         z         \n\t"
        "mov         r30,         r7        \n\t"
        "lpm         r13,         z         \n\t"
        // AddRoundConstant and AddRoundKeys
        // After 'SubColumn and ShiftRow', the registers are in
        // right order.
        //               s0  s1  s2  s3       r8  r9  r10 r11
        //               s4  s5  s6  s7   =   r12 r13 r14 r15
        // Cipher State: s8  s9  s10 s11  =   r16 r17 r18 r19
        //               s12 s13 s14 s15      r20 r21 r22 r23
        #if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "movw        r30,         r28       \n\t"
        "lpm         r6,          z+        \n\t"
        "eor         r8,          r6        \n\t"
        "lpm         r6,          z+        \n\t"
        "eor         r9,          r6        \n\t"
        "lpm         r6,          z+        \n\t"
        "eor         r10,         r6        \n\t"
        "lpm         r6,          z+        \n\t"
        "eor         r11,         r6        \n\t"
        "lpm         r6,          z+        \n\t"
        "eor         r12,         r6        \n\t"
        "lpm         r6,          z+        \n\t"
        "eor         r13,         r6        \n\t"
        "lpm         r6,          z+        \n\t"
        "eor         r14,         r6        \n\t"
        "lpm         r6,          z+        \n\t"
        "eor         r15,         r6        \n\t"
        "movw        r28,         r30       \n\t"
        "eor         r16,         r25       \n\t"
        #else
        "ld          r6,          y+        \n\t"
        "eor         r8,          r6        \n\t"
        "ld          r6,          y+        \n\t"
        "eor         r9,          r6        \n\t"
        "ld          r6,          y+        \n\t"
        "eor         r10,         r6        \n\t"
        "ld          r6,          y+        \n\t"
        "eor         r11,         r6        \n\t"
        "ld          r6,          y+        \n\t"
        "eor         r12,         r6        \n\t"
        "ld          r6,          y+        \n\t"
        "eor         r13,         r6        \n\t"
        "ld          r6,          y+        \n\t"
        "eor         r14,         r6        \n\t"
        "ld          r6,          y+        \n\t"
        "eor         r15,         r6        \n\t"
        "eor         r16,         r25       \n\t"
        #endif
        // MixColumn
        // After 'MixColumn', the registers are in wrong order.
        // And this is recovered to right order in 'SubColumn
        // with ShiftRow' of the next round. By doing so, the
        // instructions to implement 'ShiftRow' can be redecues.
        // eor  s4,  s8
        // eor  s8,  s0
        // eor  s12, s8
        //               s13 s14 s15 s12      r21 r22 r23 r20
        //               s0  s1  s2  s3   =   r8  r9  r10 r11
        // Cipher State: s7  s4  s5  s6   =   r15 r12 r13 r14
        //               s10 s11 s8  s9       r18 r19 r16 r17
        // first column
        "eor         r15,         r18       \n\t"
        "eor         r18,         r8        \n\t"
        "eor         r21,         r18       \n\t"
        // second column
        "eor         r12,         r19       \n\t"
        "eor         r19,         r9        \n\t"
        "eor         r22,         r19       \n\t"
        // third column
        "eor         r13,         r16       \n\t"
        "eor         r16,         r10       \n\t"
        "eor         r23,         r16       \n\t"
        // fourth column
        "eor         r14,         r17       \n\t"
        "eor         r17,         r11       \n\t"
        "eor         r20,         r17       \n\t"
        "dec         r24                    \n\t"
        #if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
        "breq        enc_end                \n\t"
        "rjmp        enc_loop               \n\t"
    "enc_end:                               \n\t"
        #else
        "brne        enc_loop               \n\t"
        #endif
        // store cipher text
        "st          x,           r17       \n\t"
        "st          -x,          r16       \n\t"
        "st          -x,          r19       \n\t"
        "st          -x,          r18       \n\t"
        "st          -x,          r14       \n\t"
        "st          -x,          r13       \n\t"
        "st          -x,          r12       \n\t"
        "st          -x,          r15       \n\t"
        "st          -x,          r11       \n\t"
        "st          -x,          r10       \n\t"
        "st          -x,          r9        \n\t"
        "st          -x,          r8        \n\t"
        "st          -x,          r20       \n\t"
        "st          -x,          r23       \n\t"
        "st          -x,          r22       \n\t"
        "st          -x,          r21       \n\t"
        // --------------------------------------
        "pop         r29        \n\t"
        "pop         r28        \n\t"
        "pop         r17        \n\t"
        "pop         r16        \n\t"
        "pop         r15        \n\t"
        "pop         r14        \n\t"
        "pop         r13        \n\t"
        "pop         r12        \n\t"
        "pop         r11        \n\t"
        "pop         r10        \n\t"
        "pop         r9         \n\t"
        "pop         r8         \n\t"
        "pop         r7         \n\t"
        "pop         r6         \n\t"
    :
    : [block] "x" (block), [roundKeys] "" (roundKeys), [SBOX] "" (SBOX));
}

#elif defined MSP
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    /* r4-r11  : cipher state                */
    /* r12     : temp use                    */
    /* r13     : currentRound                */
    /* r14     : point to round keys         */
    /* r15     : point to block              */
    asm volatile(
        "push        r4         \n\t"
        "push        r5         \n\t"
        "push        r6         \n\t"
        "push        r7         \n\t"
        "push        r8         \n\t"
        "push        r9         \n\t"
        "push        r10        \n\t"
        "push        r11        \n\t"
        "mov         #40,       r13          \n\t"
        "mov         0(r15),    r4           \n\t"
        "mov         2(r15),    r5           \n\t"
        "mov         4(r15),    r6           \n\t"
        "mov         6(r15),    r7           \n\t"
        "mov         8(r15),    r8           \n\t"
        "mov         10(r15),   r9           \n\t"
        "mov         12(r15),   r10          \n\t"
        "mov         14(r15),   r11          \n\t"
    "enc_loop:                               \n\t"
        // SubColumn, AddConstant, AddRoundKeys and ShiftRows
        "mov.b       r4,        r12          \n\t" // s0' = SBOX[s0]^(rks[0]^rc)
        "mov.b       SBOX(r12), r12          \n\t"
        "xor.b       @r14+,     r12          \n\t"
        "mov.b       r12,       0(r15)       \n\t"
        "swpb        r4                      \n\t" // s1' = SBOX[s1]^rks[1]
        "mov.b       r4,        r12          \n\t"
        "mov.b       SBOX(r12), r12          \n\t"
        "xor.b       @r14+,     r12          \n\t"
        "mov.b       r12,       1(r15)       \n\t"
        "mov.b       r5,        r12          \n\t" // s2' = SBOX[s2]^rks[2]
        "mov.b       SBOX(r12), r12          \n\t"
        "xor.b       @r14+,     r12          \n\t"
        "mov.b       r12,       2(r15)       \n\t"
        "swpb        r5                      \n\t" // s3' = SBOX[s3]^rks[3]
        "mov.b       r5,        r12          \n\t"
        "mov.b       SBOX(r12), r12          \n\t"
        "xor.b       @r14+,     r12          \n\t"
        "mov.b       r12,       3(r15)       \n\t"
        "mov.b       r6,        r12          \n\t" // s5' = SBOX[s4]^(rks[4]^rc)
        "mov.b       SBOX(r12), r12          \n\t"
        "xor.b       @r14+,     r12          \n\t"
        "mov.b       r12,       5(r15)       \n\t"
        "swpb        r6                      \n\t"
        "mov.b       r6,        r12          \n\t" // s6' = SBOX[s5]^rks[s5]
        "mov.b       SBOX(r12), r12          \n\t"
        "xor.b       @r14+,     r12          \n\t"
        "mov.b       r12,       6(r15)       \n\t"
        "mov.b       r7,        r12          \n\t" // s7' = SBOX[s6]^rks[s6]
        "mov.b       SBOX(r12), r12          \n\t"
        "xor.b       @r14+,     r12          \n\t"
        "mov.b       r12,       7(r15)       \n\t"
        "swpb        r7                      \n\t" // s4' = SBOX[s7]^rks[7]
        "mov.b       r7,        r12          \n\t"
        "mov.b       SBOX(r12), r12          \n\t"
        "xor.b       @r14+,     r12          \n\t"
        "mov.b       r12,       4(r15)       \n\t"
        "mov.b       r8,        r12          \n\t" // s10' = SBOX[s8]^rc
        "mov.b       SBOX(r12), r12          \n\t"
        "xor.b       #0x0002,   r12          \n\t"
        "mov.b       r12,       10(r15)      \n\t" // s11' = SBOX[s9]
        "swpb        r8                      \n\t"
        "mov.b       r8,        r12          \n\t" // s8' = SBOX[s10]
        "mov.b       SBOX(r12), 11(r15)      \n\t"
        "mov.b       r9,        r12          \n\t"
        "mov.b       SBOX(r12), 8(r15)       \n\t"
        "swpb        r9                      \n\t" // s9' = SBOX[s11]
        "mov.b       r9,        r12          \n\t"
        "mov.b       SBOX(r12), 9(r15)       \n\t"
        "mov.b       r10,       r12          \n\t" // s15' = SBOX[s12]
        "mov.b       SBOX(r12), 15(r15)      \n\t"
        "swpb        r10                     \n\t" // s12' = SBOX[s13]
        "mov.b       r10,       r12          \n\t"
        "mov.b       SBOX(r12), 12(r15)      \n\t"
        "mov.b       r11,       r12          \n\t" // s13' = SBOX[s14]
        "mov.b       SBOX(r12), 13(r15)      \n\t"
        "swpb        r11                     \n\t" // s14' = SBOX[s15]
        "mov.b       r11,       r12          \n\t"
        "mov.b       SBOX(r12), 14(r15)      \n\t"
        // MixColumn
        // xor  s8,  s4
        // xor  s0,  s8
        // xor  s8,  s12
        "mov         0(r15),    r6           \n\t"
        "mov         2(r15),    r7           \n\t"
        "mov         4(r15),    r8           \n\t"
        "mov         6(r15),    r9           \n\t"
        "mov         8(r15),    r10          \n\t"
        "mov         10(r15),   r11          \n\t"
        "mov         12(r15),   r4           \n\t"
        "mov         14(r15),   r5           \n\t"
        // part 1
        "xor         r10,       r8           \n\t"
        "xor         r6,        r10          \n\t"
        "xor         r10,       r4           \n\t"
        // part 2
        "xor         r11,       r9           \n\t"
        "xor         r7,        r11          \n\t"
        "xor         r11,       r5           \n\t"
    "dec             r13                     \n\t"
    "jne             enc_loop                \n\t"
        "mov         r4,        0(r15)       \n\t"
        "mov         r5,        2(r15)       \n\t"
        "mov         r6,        4(r15)       \n\t"
        "mov         r7,        6(r15)       \n\t"
        "mov         r8,        8(r15)       \n\t"
        "mov         r9,        10(r15)      \n\t"
        "mov         r10,       12(r15)      \n\t"
        "mov         r11,       14(r15)      \n\t"
        "pop         r11        \n\t"
        "pop         r10        \n\t"
        "pop         r9         \n\t"
        "pop         r8         \n\t"
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
        "mov        r8,       #40              \n\t"
        "ldr        r9,       =SBOX            \n\t"
        "mov        r10,      #0xff            \n\t"
        "ldmia      r0,       {r2-r5}          \n\t" // load plaintext
    "enc_loop:                                 \n\t"
        // SubColumn
        // r2 (s3  s2  s1  s0)
        // r3 (s7  s6  s5  s4)
        // r4 (s11 s10 s9  s8)
        // r5 (s15 s14 s13 s12)
        // first line
        "and        r6,       r2, #0xff        \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r2,r6,    #0, #8           \n\t"
        "and        r6,       r10, r2, lsr #8  \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r2,r6,    #8, #8           \n\t"
        "and        r6,       r10, r2, lsr #16 \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r2,r6,    #16, #8          \n\t"
        "mov        r6,       r2, lsr #24      \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r2,r6,    #24, #8          \n\t"
        // second line
        "and        r6,       r3, #0xff        \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r3,r6,    #0, #8           \n\t"
        "and        r6,       r10, r3, lsr #8  \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r3,r6,    #8, #8           \n\t"
        "and        r6,       r10, r3, lsr #16 \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r3,r6,    #16, #8          \n\t"
        "mov        r6,       r3, lsr #24      \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r3,r6,    #24, #8          \n\t"
        // first line
        "and        r6,       r4, #0xff        \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r4,r6,    #0, #8           \n\t"
        "and        r6,       r10, r4, lsr #8  \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r4,r6,    #8, #8           \n\t"
        "and        r6,       r10, r4, lsr #16 \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r4,r6,    #16, #8          \n\t"
        "mov        r6,       r4, lsr #24      \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r4,r6,    #24, #8          \n\t"
        // first line
        "and        r6,       r5, #0xff        \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r5,r6,    #0, #8           \n\t"
        "and        r6,       r10, r5, lsr #8  \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r5,r6,    #8, #8           \n\t"
        "and        r6,       r10, r5, lsr #16 \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r5,r6,    #16, #8          \n\t"
        "mov        r6,       r5, lsr #24      \n\t"
        "ldrb       r6,       [r9,r6]          \n\t"
        "bfi        r5,r6,    #24, #8          \n\t"
        // AddRoundKey and AddRoundConst
        "ldrd       r6,r7,    [r1,#0]          \n\t"
        "adds       r1,       r1, #8           \n\t"
        "eors       r2,       r2, r6           \n\t"
        "eors       r3,       r3, r7           \n\t"
        "eors       r4,       r4, #0x02        \n\t"
        // ShiftRow
        // The data is in little endian, so ShiftRow is inverse.
        // For example, r3 = (s7 s6 s5 s4). It needs rotate shift
        // left (not right) 8 bits to to get r3 = (s6 s5 s4 s7).
        "rors       r3,       r3, #24          \n\t"
        "rors       r4,       r4, #16          \n\t"
        "rors       r5,       r5, #8           \n\t"
        // MixColumn
        // eor  k4,  k8
        // eor  k8,  k0
        // eor  k12, k8
        "eors       r3,       r3, r4           \n\t"
        "eors       r4,       r4, r2           \n\t"
        "eors       r5,       r5, r4           \n\t"
        "mov        r6,       r2               \n\t"
        "mov        r2,       r5               \n\t"
        "mov        r5,       r4               \n\t"
        "mov        r4,       r3               \n\t"
        "mov        r3,       r6               \n\t"
    "subs           r8,       r8, #1           \n\t"
    "bne            enc_loop                   \n\t"
        "stmia      r0,       {r2-r5}          \n\t" // store ciphertext
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

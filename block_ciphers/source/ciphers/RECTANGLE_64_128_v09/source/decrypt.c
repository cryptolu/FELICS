/*
 *
 * Chinese Academy of Sciences
 * State Key Laboratory of Information Security, 
 * Institute of Information Engineering
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2017 Chinese Academy of Sciences
 *
 * Written in 2017 by Luo Peng <luopeng@iie.ac.cn>
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

#include "stringify.h"

#ifdef AVR
#include "avr.h"
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
    /* r14-r21 : cipher text             */
    /* r22-r23 : temp use                */
    /* r24     : currentRound            */
    /* r25     : const 0                 */
    /* r26:r27 : X point to cipher text  */
    /* r30:r31 : Z roundKeys             */
    asm volatile (
    "push       r14      \n\t"
    "push       r15      \n\t"
    "push       r16      \n\t"
    "push       r17      \n\t"
    "clr        r25         \n\t"
    #if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
    "ldi     r24,    200    \n\t"
    #else
    "ldi     r24,    208    \n\t"
    #endif
    "add     r30,    r24    \n\t"
    "adc     r31,    r25    \n\t"
    "ldi     r24,    25     \n\t"
    "ld      r14,    x+     \n\t"
    "ld      r15,    x+     \n\t"
    "ld      r16,    x+     \n\t"
    "ld      r17,    x+     \n\t"
    "ld      r18,    x+     \n\t"
    "ld      r19,    x+     \n\t"
    "ld      r20,    x+     \n\t"
    "ld      r21,    x      \n\t"
    "dec_loop:              \n\t"
    // Inverse AddRoundKey
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
    STR(dec_keyxor_flash(r14, r15, r16, r17, r18, r19, r20, r21, r22))
#else
    STR(dec_keyxor_ram(r14, r15, r16, r17, r18, r19, r20, r21, r22))
#endif
    // Inverse ShiftRow
    "bst     r16,    0      \n\t"
    "ror     r17            \n\t"
    "ror     r16            \n\t"
    "bld     r17,    7      \n\t"
    "swap    r18            \n\t"
    "swap    r19            \n\t"
    "movw    r22,    r18    \n\t"
    "eor     r23,    r22    \n\t"
    "andi    r23,    0x0f   \n\t"
    "eor     r18,    r23    \n\t"
    "eor     r19,    r23    \n\t"
    "lsl     r20            \n\t"
    "rol     r21            \n\t"
    "adc     r20,    r25    \n\t"
    "lsl     r20            \n\t"
    "rol     r21            \n\t"
    "adc     r20,    r25    \n\t"
    "lsl     r20            \n\t"
    "rol     r21            \n\t"
    "adc     r20,    r25    \n\t"
    // Inverse SubColumn
    STR(invert_sbox(r14, r15, r16, r17, r18, r19, r20, r21, r22, r23))
    "dec     r24            \n\t"
    "breq    last_round     \n\t"
    "rjmp    dec_loop       \n\t"
    "last_round:            \n\t"
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
    STR(dec_keyxor_flash(r14, r15, r16, r17, r18, r19, r20, r21, r22))
#else
    STR(dec_keyxor_ram(r14, r15, r16, r17, r18, r19, r20, r21, r22))
#endif
    "st      x,      r21    \n\t"
    "st      -x,     r20    \n\t"
    "st      -x,     r19    \n\t"
    "st      -x,     r18    \n\t"
    "st      -x,     r17    \n\t"
    "st      -x,     r16    \n\t"
    "st      -x,     r15    \n\t"
    "st      -x,     r14    \n\t"
    "pop     r17     \n\t"
    "pop     r16     \n\t"
    "pop     r15     \n\t"
    "pop     r14     \n\t"
    :
    : [block] "x" (block), [roundKeys] "z" (roundKeys));
}

#elif defined(MSP)
#include "msp.h"
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
    /* r4-r7   : cipher text        */
    /* r9      : #16                */
    /* r12     : temp use           */
    /* r13     : temp use           */
    /* r14     : point to roundKeys */
    /* r15     : pointer to block   */
    asm volatile (
    "push    r4     \n\t"
    "push    r5     \n\t"
    "push    r6     \n\t"
    "push    r7     \n\t"
    "push    r9     \n\t"
    "mov     @r15+,    r4     \n\t"
    "mov     @r15+,    r5     \n\t"
    "mov     @r15+,    r6     \n\t"
    "mov     @r15+,    r7     \n\t"
    "add     #200,     r14    \n\t"
    "mov     #16,      r9     \n\t"
    // 1-5
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    // 6-10
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    // 11-15
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    // 16-20
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    // 21-25
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    STR(dec_round(r4, r5, r6, r7, r12, r13))
    "xor     @r14+,    r4     \n\t"
    "xor     @r14+,    r5     \n\t"
    "xor     @r14+,    r6     \n\t"
    "xor     @r14+,    r7     \n\t"
    "mov     r4,       -8(r15)\n\t"
    "mov     r5,       -6(r15)\n\t"
    "mov     r6,       -4(r15)\n\t"
    "mov     r7,       -2(r15)\n\t"
    "pop     r9     \n\t"
    "pop     r7     \n\t"
    "pop     r6     \n\t"
    "pop     r5     \n\t"
    "pop     r4     \n\t"
    :
    : [block] "m" (block), [roundKeys] "m" (roundKeys)); 
}

#elif defined(ARM)
#include "arm.h"
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
    /* r0  - point of block       */
    /* r1  - point of round keys  */
    /* r2  - c0 16 bits           */
    /* r3  - c1                   */
    /* r4  - c2                   */
    /* r5  - c3 16 bits           */
    /* r6-r8  temp use            */
    asm volatile (
    "stmdb   sp!,   {r2-r8}           \n\t"
    "adds    r1,    r1,   #200        \n\t"
    "ldm     r0,    {r2,r4}           \n\t"
    "mov     r3,    r2,lsr #16        \n\t"
    "mov     r5,    r4,lsr #16        \n\t"
    // 1-5
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    // 6-10
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    // 11-15
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    // 16-20
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    // 21-25
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    STR(dec_round(r2, r3, r4, r5, r6, r7, r8))
    // last AddRoundKey and store plain text
    "ldm     r1!,   {r6, r7}          \n\t"
    "bfi     r2,    r3, #16, #16      \n\t"
    "bfi     r4,    r5, #16, #16      \n\t"
    "eors    r2,    r2,   r6          \n\t"
    "eors    r4,    r4,   r7          \n\t"
    "str     r2,    [r0]              \n\t"
    "str     r4,    [r0, #4]          \n\t"
    "ldmia   sp!,   {r2-r8}           \n\t"
    :
    : [block] "r" (block), [roundKeys] "r" (roundKeys));
}

#else
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
    uint16_t *block16 = (uint16_t*)block;
    uint16_t *roundKeys16 = (uint16_t*)roundKeys;
    // point to the start address of round 26
    roundKeys16 += 100;

    uint16_t w0 = *block16;
    uint16_t w1 = *(block16+1);
    uint16_t w2 = *(block16+2);
    uint16_t w3 = *(block16+3);

    uint16_t sbox0;
    uint8_t i;
    for ( i = 0; i < NUMBER_OF_ROUNDS; ++i ) {
        //Inverse AddRoundKey
        w0 ^= READ_ROUND_KEY_WORD(*(roundKeys16));
        w1 ^= READ_ROUND_KEY_WORD(*(roundKeys16+1));
        w2 ^= READ_ROUND_KEY_WORD(*(roundKeys16+2));
        w3 ^= READ_ROUND_KEY_WORD(*(roundKeys16+3));
        roundKeys16 -= 4;
        // Inverse ShiftRow
        w1 = (w1>>1  | w1 << 15);
        w2 = (w2>>12 | w2 << 4);
        w3 = (w3>>13 | w3 << 3);
        // Invert SubColumn
        sbox0 =  w0;
        w0    &= w2;
        w0    ^= w3;
        w3    |= sbox0;
        w3    ^= w2;
        w1    ^= w3;
        w2    =  w1;
        w1    ^= sbox0;
        w1    ^= w0;
        w3    =  ~w3;
        sbox0 =  w3;
        w3    |= w1;
        w3    ^= w0;
        w0    &= w1;
        w0    ^= sbox0;
    }
    // last AddRoundKey
    w0 ^= READ_ROUND_KEY_WORD(*(roundKeys16));
    w1 ^= READ_ROUND_KEY_WORD(*(roundKeys16+1));
    w2 ^= READ_ROUND_KEY_WORD(*(roundKeys16+2));
    w3 ^= READ_ROUND_KEY_WORD(*(roundKeys16+3));
    // store plain text
    *block16 = w0;
    *(block16+1) = w1;
    *(block16+2) = w2;
    *(block16+3) = w3;
}
#endif

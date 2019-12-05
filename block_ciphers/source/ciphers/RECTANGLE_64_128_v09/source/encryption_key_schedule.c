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
 * Written in 2017 by Luo Peng <luopeng@iie.ac.cn>,
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
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    /* r7      : current round     */
    /* r8-r23  : key state         */
    /* r24-r25 : temp use          */
    /* r26:r27 : point to key
               : point to roundKeys*/
    /* r30:r31 : Z point to RC     */
    asm volatile (
    "push   r7       \n\t"
    "push   r8       \n\t"
    "push   r9       \n\t"
    "push   r10      \n\t"
    "push   r11      \n\t"
    "push   r12      \n\t"
    "push   r13      \n\t"
    "push   r14      \n\t"
    "push   r15      \n\t"
    "push   r16      \n\t"
    "push   r17      \n\t"
    // set currentRound
    "ldi    r24,     25      \n\t"
    "mov    r7,      r24     \n\t"
    // load master keys
    "ld     r8,      x+      \n\t"
    "ld     r9,      x+      \n\t"
    "ld     r10,     x+      \n\t"
    "ld     r11,     x+      \n\t"
    "ld     r12,     x+      \n\t"
    "ld     r13,     x+      \n\t"
    "ld     r14,     x+      \n\t"
    "ld     r15,     x+      \n\t"
    "ld     r16,     x+      \n\t"
    "ld     r17,     x+      \n\t"
    "ld     r18,     x+      \n\t"
    "ld     r19,     x+      \n\t"
    "ld     r20,     x+      \n\t"
    "ld     r21,     x+      \n\t"
    "ld     r22,     x+      \n\t"
    "ld     r23,     x       \n\t"
    "movw   r26,     r30     \n\t"
    "ldi    r30,     lo8(RC) \n\t"
    "ldi    r31,     hi8(RC) \n\t"
    // store round keys
    "st     x+,      r8      \n\t"
    "st     x+,      r9      \n\t"
    "st     x+,      r12     \n\t"
    "st     x+,      r13     \n\t"
    "st     x+,      r16     \n\t"
    "st     x+,      r17     \n\t"
    "st     x+,      r20     \n\t"
    "st     x+,      r21     \n\t"
    "extend_loop:            \n\t"
    STR(key_sbox(r8, r12, r16, r20, r24, r25))
    "movw   r24,     r20     \n\t"
    "movw   r20,     r8      \n\t"
    "movw   r8,      r12     \n\t"
    "movw   r12,     r16     \n\t"
    "movw   r16,     r24     \n\t"
    "eor    r8,      r11     \n\t"
    "eor    r9,      r20     \n\t"
    "eor    r16,     r18     \n\t"
    "eor    r17,     r19     \n\t"
    "movw   r24,     r22     \n\t"
    "movw   r22,     r10     \n\t"
    "movw   r10,     r14     \n\t"
    "movw   r14,     r18     \n\t"
    "movw   r18,     r24     \n\t"
    "eor    r10,     r21     \n\t"
    "eor    r11,     r22     \n\t"
    "eor    r18,     r12     \n\t"
    "eor    r19,     r13     \n\t"
    "lpm    r24,     z+      \n\t"
    "eor    r8,      r24     \n\t"
    // store round keys
    "st     x+,      r8      \n\t"
    "st     x+,      r9      \n\t"
    "st     x+,      r12     \n\t"
    "st     x+,      r13     \n\t"
    "st     x+,      r16     \n\t"
    "st     x+,      r17     \n\t"
    "st     x+,      r20     \n\t"
    "st     x+,      r21     \n\t"
    "dec    r7               \n\t"
    "brne   extend_loop      \n\t"
    "pop    r17      \n\t"
    "pop    r16      \n\t"
    "pop    r15      \n\t"
    "pop    r14      \n\t"
    "pop    r13      \n\t"
    "pop    r12      \n\t"
    "pop    r11      \n\t"
    "pop    r10      \n\t"
    "pop    r9       \n\t"
    "pop    r8       \n\t"
    "pop    r7       \n\t"
    :
    : [key] "x" (key), [roundKeys] "z" (roundKeys), [RC] "" (RC)); 
}

#elif defined(MSP)
#include "msp.h"
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    /* r4-r11  : key state           */
    /* r12     : temp use            */
    /* r13     : currentRound        */
    /* r14     : point to roundKeys  */
    /* r15     : point to key and RC */
    asm volatile (
    "push     r4      \n\t"
    "push     r5      \n\t"
    "push     r6      \n\t"
    "push     r7      \n\t"
    "push     r8      \n\t"
    "push     r9      \n\t"
    "push     r10     \n\t"
    "push     r11     \n\t"
    "mov      @r15+,  r4       \n\t"
    "mov      @r15+,  r5       \n\t"
    "mov      @r15+,  r6       \n\t"
    "mov      @r15+,  r7       \n\t"
    "mov      @r15+,  r8       \n\t"
    "mov      @r15+,  r9       \n\t"
    "mov      @r15+,  r10      \n\t"
    "mov      @r15+,  r11      \n\t"
    // make some place to store temp data
    "sub      #10,    r1       \n\t"
    // store round keys
    "mov      r4,     0(r14)   \n\t"
    "mov      r6,     2(r14)   \n\t"
    "mov      r8,     4(r14)   \n\t"
    "mov      r10,    6(r14)   \n\t"
    "add      #8,     r14      \n\t"
    "mov      %[RC],  r15      \n\t"
    "mov      #25,    r13      \n\t"
    "extend_loop:              \n\t"
    // sbox
    "mov      r15,    8(r1)    \n\t"
    "mov      r10,    6(r1)    \n\t"
    "mov      r8,     4(r1)    \n\t"
    "mov      r6,     2(r1)    \n\t"
    "mov      r4,     0(r1)    \n\t"
    STR(ksche_sbox(r4, r6, r8, r10, r12, r15))
    "mov      #0xff00,r15      \n\t"
    "mov      @r1+,   r12      \n\t"
    "and      r15,    r12      \n\t"
    "xor      r12,    r4       \n\t"
    "mov      @r1+,   r12      \n\t"
    "and      r15,    r12      \n\t"
    "xor      r12,    r6       \n\t"
    "mov      @r1+,   r12      \n\t"
    "and      r15,    r12      \n\t"
    "xor      r12,    r8       \n\t"
    "mov      @r1+,   r12      \n\t"
    "and      r15,    r12      \n\t"
    "xor      r12,    r10      \n\t"
    "sub      #8,     r1       \n\t"
    // generalized feistel
    "mov      r5,     r15      \n\t"
    "mov      r6,     r12      \n\t"
    "mov      r7,     r5       \n\t"
    "mov      r8,     r6       \n\t"
    "mov      r9,     r7       \n\t"
    "mov      r10,    r8       \n\t"
    "mov      r11,    r9       \n\t"
    "mov      r4,     r10      \n\t"
    "mov      r15,    r11      \n\t"
    "mov      r12,    0(r1)    \n\t"
    "swpb     r4               \n\t"
    "swpb     r15              \n\t"
    "mov.b    r4,     r12      \n\t"
    "xor.b    r15,    r12      \n\t"
    "xor      r12,    r15      \n\t"
    "xor      r12,    r4       \n\t"
    "xor      @r1,    r4       \n\t"
    "xor      r15,    r5       \n\t"
    "xor      r7,     r8       \n\t"
    "xor      r6,     r9       \n\t"
    // add round constant
    "mov      8(r1),  r15      \n\t"
    "mov.b    @r15+,  r12      \n\t"
    "xor      r12,    r4       \n\t"
    // store last round keys
    "mov      r4,     0(r14)   \n\t"
    "mov      r6,     2(r14)   \n\t"
    "mov      r8,     4(r14)   \n\t"
    "mov      r10,    6(r14)   \n\t"
    "add      #8,     r14      \n\t"
    "dec      r13              \n\t"
    "jne      extend_loop      \n\t"
    "add      #10,    r1       \n\t"
    "pop      r11     \n\t"
    "pop      r10     \n\t"
    "pop      r9      \n\t"
    "pop      r8      \n\t"
    "pop      r7      \n\t"
    "pop      r6      \n\t"
    "pop      r5      \n\t"
    "pop      r4      \n\t"
    :
    : [key] "m" (key), [roundKeys] "m" (roundKeys), [RC] "" (RC));
}

#elif defined(ARM)
#include "arm.h"
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    /* r0  - point of master key and
           - point of Round Constants */
    /* r1  - point of round keys      */
    /* r2-r5 - k0-k3                  */
    /* r6  - temp 0                   */
    /* r7  - temp 1                   */
    /* r8  - loop counter             */
    /* r9-r12 - temp k0-r3            */
    asm volatile (
    "stmdb    sp!,      {r2-r12}        \n\t"
    "ldmia    r0,       {r2-r5}         \n\t"
    "mov      r8,       #25             \n\t"
    "ldr      r0,       =(RC-1)         \n\t"
    // store round keys
    "mov      r6,       r2              \n\t"
    "bfi      r6,       r3,#16,#16      \n\t"
    "mov      r7,       r4              \n\t"
    "bfi      r7,       r5,#16,#16      \n\t"
    "stm      r1!,      {r6,r7}         \n\t"
    "extend_loop:                       \n\t"
    // sbox
    "mov      r9,       r2              \n\t"
    "mov      r10,      r3              \n\t"
    "mov      r11,      r4              \n\t"
    "mov      r12,      r5              \n\t"
    STR(sbox(r2, r3, r4, r5, r6, r7))
    "bfi      r9,       r2,#0,#8        \n\t"
    "bfi      r10,      r3,#0,#8        \n\t"
    "bfi      r11,      r4,#0,#8        \n\t"
    "bfi      r12,      r5,#0,#8        \n\t"
    // generalized feistel
    "eor      r2, r10,  r9,ror #24      \n\t"
    "mov      r3, r11                   \n\t"
    "eor      r4, r12,  r11,ror #16     \n\t"
    "mov      r5, r9                    \n\t"
    // add round constant
    "ldrb     r6,       [r0, #1]!       \n\t"
    "eors     r2,       r6              \n\t"
    // store round keys
    "mov      r6,       r2              \n\t"
    "bfi      r6,       r3,#16,#16      \n\t"
    "mov      r7,       r4              \n\t"
    "bfi      r7,       r5,#16,#16      \n\t"
    "stm      r1!,      {r6,r7}         \n\t"
    // loop control
    "subs     r8,       r8, #1          \n\t"
    "bne      extend_loop               \n\t"
    "ldmia    sp!,      {r2-r12}        \n\t"
    :
    : [key] "r" (key), [roundKeys] "r" (roundKeys));
}

#else
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    uint8_t key8[16];
    uint8_t i;
    for ( i = 0; i < KEY_SIZE; ++i) {
        key8[i] = key[i];
    }

    uint16_t *key16 = (uint16_t*)key8;
    uint16_t *roundKeys16 = (uint16_t*)roundKeys;

    roundKeys16[0] = key16[0];
    roundKeys16[1] = key16[2];
    roundKeys16[2] = key16[4];
    roundKeys16[3] = key16[6];

    uint8_t sbox0, sbox1;
    uint16_t halfRow2;
    uint32_t tempRow0;
    for ( i = 1; i <= NUMBER_OF_ROUNDS; ++i) {
        // sbox
        sbox0    =  key8[8];
        key8[8]  ^= key8[4];
        key8[4]  =  ~key8[4];
        sbox1    =  key8[0];
        key8[0]  &= key8[4];
        key8[4]  |= key8[12];
        key8[4]  ^= sbox1;
        key8[12] ^= sbox0;
        key8[0]  ^= key8[12];
        key8[12] &= key8[4];
        key8[12] ^= key8[8];
        key8[8]  |= key8[0];
        key8[8]  ^= key8[4];
        key8[4]  ^= sbox0;
        // generalized feistel
        tempRow0 = *((uint32_t*)key8);
        *((uint32_t*)key8) = (tempRow0<<8 | tempRow0>>24) ^ *((uint32_t*)key8+1);
        *((uint32_t*)key8+1) = *((uint32_t*)key8+2);
        halfRow2 = *(key16+4);
        *(key16+4) = *(key16+5) ^ *(key16+6);
        *(key16+5) = halfRow2 ^ *(key16+7);
        *((uint32_t*)key8+3) = tempRow0;
        // add round constant
        *key8 ^= READ_RC_BYTE(RC[i-1]);
        // store round keys
        roundKeys16[4*i] = key16[0];
        roundKeys16[4*i+1] = key16[2];
        roundKeys16[4*i+2] = key16[4];
        roundKeys16[4*i+3] = key16[6];
    }
}
#endif

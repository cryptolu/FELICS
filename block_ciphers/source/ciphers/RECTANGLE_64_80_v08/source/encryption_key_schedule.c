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
    /* r8-r13  : temp use              */
    /* r14-r15 : k8-k9                 */
    /* r16-r23 : k0-k7                 */
    /* r24     : 0xf0                  */
    /* r25     : currentRound          */
    /* r26:r27 : X point to key        */
    /* r28:r29 : Y point to roundKeys  */
    /* r30:r31 : Z point to RC         */
    asm volatile (
    "push    r11    \n\t"
    "push    r12    \n\t"
    "push    r13    \n\t"
    "push    r14    \n\t"
    "push    r15    \n\t"
    "push    r16    \n\t"
    "push    r17    \n\t"
    "push    r28    \n\t"
    "push    r29    \n\t"
    // load master keys
    "ld      r16,   x+       \n\t"
    "ld      r17,   x+       \n\t"
    "ld      r18,   x+       \n\t"
    "ld      r19,   x+       \n\t"
    "ld      r20,   x+       \n\t"
    "ld      r21,   x+       \n\t"
    "ld      r22,   x+       \n\t"
    "ld      r23,   x+       \n\t"
    "ld      r14,   x+       \n\t"
    "ld      r15,   x+       \n\t"
    "movw    r28,   r30      \n\t"
    "ldi     r30,   lo8(RC)  \n\t"
    "ldi     r31,   hi8(RC)  \n\t"
    "ldi     r25,   25       \n\t"
    "mov     r11,   r25      \n\t"
    // store round keys
    "st      y+,    r16      \n\t"
    "st      y+,    r17      \n\t"
    "st      y+,    r18      \n\t"
    "st      y+,    r19      \n\t"
    "st      y+,    r20      \n\t"
    "st      y+,    r21      \n\t"
    "st      y+,    r22      \n\t"
    "st      y+,    r23      \n\t"
    // key schedule
    "extend_loop:            \n\t"
    "mov     r24,   r16      \n\t"
    "mov     r25,   r18      \n\t"
    "mov     r26,   r20      \n\t"
    "mov     r27,   r22      \n\t"
    // sbox
    STR(key_sbox(r16, r18, r20, r22, r12, r13))
    "andi    r16,    0x0f    \n\t"
    "andi    r24,    0xf0    \n\t"
    "eor     r16,    r24     \n\t"
    "andi    r18,    0x0f    \n\t"
    "andi    r25,    0xf0    \n\t"
    "eor     r18,    r25     \n\t"
    "andi    r20,    0x0f    \n\t"
    "andi    r26,    0xf0    \n\t"
    "eor     r20,    r26     \n\t"
    "andi    r22,    0x0f    \n\t"
    "andi    r27,    0xf0    \n\t"
    "eor     r22,    r27     \n\t"
    // generalized feistel
    "movw    r24,    r22     \n\t"
    "movw    r22,    r14     \n\t"
    "movw    r14,    r16     \n\t"
    "movw    r16,    r18     \n\t"
    "movw    r18,    r20     \n\t"
    "movw    r20,    r24     \n\t"
    "eor     r16,    r15     \n\t"
    "eor     r17,    r14     \n\t"
    "swap    r24             \n\t"
    "swap    r25             \n\t"
    "eor     r22,    r24     \n\t"
    "eor     r23,    r25     \n\t"
    "eor     r25,    r24     \n\t"
    "andi    r25,    0xf0    \n\t"
    "eor     r22,    r25     \n\t"
    "eor     r23,    r25     \n\t"
    // add round constant
    "lpm     r24,    z+      \n\t"
    "eor     r16,    r24     \n\t"
    // store round keys
    "st      y+,    r16      \n\t"
    "st      y+,    r17      \n\t"
    "st      y+,    r18      \n\t"
    "st      y+,    r19      \n\t"
    "st      y+,    r20      \n\t"
    "st      y+,    r21      \n\t"
    "st      y+,    r22      \n\t"
    "st      y+,    r23      \n\t"
    "dec     r11             \n\t"
    "brne    extend_loop     \n\t"
    "pop     r29    \n\t"
    "pop     r28    \n\t"
    "pop     r17    \n\t"
    "pop     r16    \n\t"
    "pop     r15    \n\t"
    "pop     r14    \n\t"
    "pop     r13    \n\t"
    "pop     r12    \n\t"
    "pop     r11    \n\t"
    :
    : [key] "x" (key), [roundKeys] "z" (roundKeys), [RC] "" (RC)); 
}

#elif defined(MSP)
#include "msp.h"
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    /* r4-r7   : temp use             */
    /* r8-r12  : key state            */
    /* r13     : currentRound         */
    /* r14     : point to roundKeys   */
    /* r15     : point to key and RC  */
    asm volatile (
    "push     r4      \n\t"
    "push     r5      \n\t"
    "push     r6      \n\t"
    "push     r7      \n\t"
    "push     r8      \n\t"
    "push     r9      \n\t"
    "push     r10     \n\t"
    "push     r11     \n\t"
    "mov      @r15+,  r8        \n\t"
    "mov      @r15+,  r9        \n\t"
    "mov      @r15+,  r10       \n\t"
    "mov      @r15+,  r11       \n\t"
    "mov      @r15+,  r12       \n\t"
    "mov      r8,     0(r14)    \n\t"
    "mov      r9,     2(r14)    \n\t"
    "mov      r10,    4(r14)    \n\t"
    "mov      r11,    6(r14)    \n\t"
    "mov      %[RC],  r15       \n\t"
    "mov      #25,    r13       \n\t"
    // make some place to store temp data
    "sub      #4,     r1        \n\t"
    // key schedule
    "extend_loop:               \n\t"
    // sbox
    "mov      r11,    2(r1)     \n\t"
    "mov      r10,    0(r1)     \n\t"
    "mov      r9,     r5        \n\t"
    "mov      r8,     r4        \n\t"
    STR(sbox(r8, r9, r10, r11, r6, r7))
    "and      #0xfff0, r4       \n\t"
    "and      #0x000f, r8       \n\t"
    "xor      r4,      r8       \n\t"
    "and      #0xfff0, r5       \n\t"
    "and      #0x000f, r9       \n\t"
    "xor      r5,      r9       \n\t"
    "mov      @r1+,    r6       \n\t"
    "and      #0xfff0, r6       \n\t"
    "and      #0x000f, r10      \n\t"
    "xor      r6,      r10      \n\t"
    "mov      @r1+,    r7       \n\t"
    "and      #0xfff0, r7       \n\t"
    "and      #0x000f, r11      \n\t"
    "xor      r7,      r11      \n\t"
    "sub      #4,      r1       \n\t"
    // generalized feistel
    "mov      r8,      r4       \n\t"
    "mov      r9,      r8       \n\t"
    "mov      r10,     r9       \n\t"
    "mov      r11,     r10      \n\t"
    "mov      r12,     r11      \n\t"
    "mov      r4,      r12      \n\t"
    "swpb     r4                \n\t"
    "xor      r4,      r8       \n\t"
    "mov      r10,     r4       \n\t"
    "bit      #1,      r4       \n\t"
    "rrc      r4                \n\t"
    "bit      #1,      r4       \n\t"
    "rrc      r4                \n\t"
    "bit      #1,      r4       \n\t"
    "rrc      r4                \n\t"
    "bit      #1,      r4       \n\t"
    "rrc      r4                \n\t"
    "xor      r4,      r11      \n\t"
    // add round constant
    "mov.b    @r15+,   r4       \n\t"
    "xor      r4,      r8       \n\t"
    "add      #8,      r14      \n\t"
    "mov      r8,      0(r14)   \n\t"
    "mov      r9,      2(r14)   \n\t"
    "mov      r10,     4(r14)   \n\t"
    "mov      r11,     6(r14)   \n\t"
    "dec      r13               \n\t"
    "jne      extend_loop       \n\t"
    "add      #4,      r1       \n\t"
    "pop      r11      \n\t"
    "pop      r10      \n\t"
    "pop      r9       \n\t"
    "pop      r8       \n\t"
    "pop      r7       \n\t"
    "pop      r6       \n\t"
    "pop      r5       \n\t"
    "pop      r4       \n\t"
    :
    : [key] "m" (key), [roundKeys] "m" (roundKeys), [RC] "" (RC));
}

#elif defined(ARM)
#include "arm.h"
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    /* r0    - point of master key
             - temp use             */
    /* r1    - point of round keys  */
    /* r2-r6 - k0-k4                */
    /* r7    - temp use             */
    /* r8    - loop counter         */
    /* r9    - point of RC          */
    /* r10-r12- temp k0-temp k2     */
    /* lr    - temp k3              */
    asm volatile (
    "stmdb    sp!,     {r2-r12,lr}\n\t"
    "mov      r8,      #25        \n\t"
    "ldr      r9,      =(RC-1)    \n\t" 
    "ldm      r0,      {r2,r4,r6} \n\t"
    "stm      r1!,     {r2,r4}    \n\t"
    "lsr      r3,      r2, #16    \n\t"
    "lsr      r5,      r4, #16    \n\t"
    "extend_loop:                 \n\t"
    // sbox
    "mov      r10,     r2         \n\t"
    "mov      r11,     r3         \n\t"
    "mov      r12,     r4         \n\t"
    "mov      lr,      r5         \n\t"
    STR(sbox(r2, r3, r4, r5, r0, r7))
    "bfi      r10,r2,  #0, #4     \n\t"
    "bfi      r11,r3,  #0, #4     \n\t"
    "bfi      r12,r4,  #0, #4     \n\t"
    "bfi      lr, r5,  #0, #4     \n\t"
    // generalized feistel
    "rev16    r7,      r10        \n\t"
    "eor      r2,      r11, r7    \n\t"
    "mov      r3,      r12        \n\t"
    "mov      r4,      lr         \n\t"
    "bfi      lr,lr,   #16, #4    \n\t"
    "eor      r5,r6,   lr, lsr #4 \n\t"
    "mov      r6,      r10        \n\t"
    // add round constant
    "ldrb     r0,      [r9, r8]   \n\t"
    "eors     r2,      r0         \n\t"
    "bfi      r2,r3,   #16, #16   \n\t"
    "bfi      r4,r5,   #16, #16   \n\t"
    "stm      r1!,     {r2,r4}    \n\t"
    "subs     r8,      #1         \n\t"
    "bne      extend_loop         \n\t"
    "ldmia    sp!,     {r2-r12,lr}\n\t"
    :
    : [key] "r" (key), [roundKeys] "r" (roundKeys));
}

#else
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    uint8_t key8[10];
    uint8_t i;
    for ( i = 0; i < KEY_SIZE; ++i) {
        key8[i] = key[i];
    }

    uint16_t *key16 = (uint16_t*)key8;
    uint16_t *roundKeys16 = (uint16_t*)roundKeys;

    roundKeys16[0] = key16[0];
    roundKeys16[1] = key16[1];
    roundKeys16[2] = key16[2];
    roundKeys16[3] = key16[3];

    uint8_t sbox0, sbox1;
    uint8_t temp[4];
    uint16_t tempk0;
    for ( i = 1; i <= NUMBER_OF_ROUNDS; ++i) {
        temp[0] = key8[0];
        temp[1] = key8[2];
        temp[2] = key8[4];
        temp[3] = key8[6];
        // sbox
        sbox0    =  key8[4];
        key8[4]  ^= key8[2];
        key8[2]  =  ~key8[2];
        sbox1    =  key8[0];
        key8[0]  &= key8[2];
        key8[2]  |= key8[6];
        key8[2]  ^= sbox1;
        key8[6]  ^= sbox0;
        key8[0]  ^= key8[6];
        key8[6]  &= key8[2];
        key8[6]  ^= key8[4];
        key8[4]  |= key8[0];
        key8[4]  ^= key8[2];
        key8[2]  ^= sbox0;
        key8[0]  =  (key8[0]&0x0f) ^ (temp[0]&0xf0);
        key8[2]  =  (key8[2]&0x0f) ^ (temp[1]&0xf0);
        key8[4]  =  (key8[4]&0x0f) ^ (temp[2]&0xf0);
        key8[6]  =  (key8[6]&0x0f) ^ (temp[3]&0xf0);
        // generalized feistel
        tempk0     =  *(key16);
        *(key16)   =  *(key16+1);
        *(key16+1) =  *(key16+2);
        *(key16+2) =  *(key16+3);
        *(key16+3) =  *(key16+4);
        *(key16+4) =  tempk0;
        *(key16)   ^= ((tempk0<<8)|(tempk0>>8));
        tempk0     =  *(key16+2);
        *(key16+3) ^= ((tempk0<<12)|(tempk0>>4));
        // add round constant
        *key8 ^= READ_RC_BYTE(RC[i-1]);

        roundKeys16[4*i]   = key16[0];
        roundKeys16[4*i+1] = key16[1];
        roundKeys16[4*i+2] = key16[2];
        roundKeys16[4*i+3] = key16[3];
    }
}
#endif

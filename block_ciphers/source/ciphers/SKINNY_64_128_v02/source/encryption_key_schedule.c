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
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    /*--------------------------------------*/
    // Round keys and round constants are eor-ed
    // and stored together
    /* r5      : 0x0f                       */
    /* r6,r7,r24,r25 : temp                 */
    /* r8-r23  : master keys                */
    /* r26     : loop control               */
    /* r27     : 0xf0                       */
    /* r26-r27 : X points to master keys    */
    /* r28-r29 : Y points to roundKeys      */
    /* r30-r31 : Z points to RC             */
    /* -------------------------------------*/
    asm volatile(
    	"push         r5         \n\t"
        "push         r6         \n\t"
        "push         r7         \n\t"
        "push         r8         \n\t"
        "push         r9         \n\t"
        "push         r10        \n\t"
        "push         r11        \n\t"
        "push         r12        \n\t"
        "push         r13        \n\t"
        "push         r14        \n\t"
        "push         r15        \n\t"
        "push         r16        \n\t"
        "push         r17        \n\t"
        "push         r28        \n\t"
        "push         r29        \n\t"
        "movw         r26,        r24       \n\t"
        "movw         r28,        r22       \n\t"
        // Load keys
        // Tweak1        Tweak2
        // r8  r9        r16 r17
        // r10 r11       r18 r19
        // r12 r13       r20 r21
        // r14 r15       r22 r23
        // 
        "ld           r8,         x+        \n\t"
        "ld           r9,         x+        \n\t"
        "ld           r10,        x+        \n\t"
        "ld           r11,        x+        \n\t"
        "ld           r12,        x+        \n\t"
        "ld           r13,        x+        \n\t"
        "ld           r14,        x+        \n\t"
        "ld           r15,        x+        \n\t"
        "ld           r16,        x+        \n\t"
        "ld           r17,        x+        \n\t"
        "ld           r18,        x+        \n\t"
        "ld           r19,        x+        \n\t"
        "ld           r20,        x+        \n\t"
        "ld           r21,        x+        \n\t"
        "ld           r22,        x+        \n\t"
        "ld           r23,        x+        \n\t"
        // Init
        "ldi          r26,        36        \n\t"
        "ldi          r27,        0x0f      \n\t"
        "mov          r5,         r27       \n\t"
        "ldi          r27,        0xf0      \n\t"
        "ldi          r30,        lo8(RC)   \n\t"
        "ldi          r31,        hi8(RC)   \n\t"
    "key_schedule_start:                    \n\t"
        // XOR RoundConstant and the TweakKeys together
        "lpm          r24,        z+        \n\t"
        "mov          r25,        r24       \n\t"
        "andi         r25,        0x0f      \n\t"
        "swap         r25                   \n\t"
        "mov          r6,         r8        \n\t" // store k0
        "eor          r6,         r25       \n\t"
        "eor          r6,         r16       \n\t"
        "st           y+,         r6        \n\t"
        "mov          r6,         r9        \n\t" // store k1
        "eor          r6,         r17       \n\t"
        "st           y+,         r6        \n\t"
        "andi         r24,        0x30      \n\t" // store k2
        "mov          r6,         r10       \n\t"
        "eor          r6,         r24       \n\t"
        "eor          r6,         r18       \n\t"
        "st           y+,         r6        \n\t"
        "mov          r6,         r11       \n\t" // store k3
        "eor          r6,         r19       \n\t"
        "st           y+,         r6        \n\t"        
        // (k0  k1 ) (k2  k3 )        (k9  k15) (k8  k13)
        // (k4  k5 ) (k6  k7 )        (k10 k14) (k12 k11)
        // (k8  k9 ) (k10 k11) -----> (k0  k1 ) (k2  k3 )
        // (k12 k13) (k14 k15)        (k4  k5 ) (k6  k7 )
        // Tweak1
        "movw         r6,         r12       \n\t"
        "movw         r12,        r8        \n\t"
        "movw         r8,         r14       \n\t"
        "movw         r14,        r10       \n\t"

        "mov          r11,        r7        \n\t"
        "and          r11,        r5        \n\t"
        "mov          r10,        r8        \n\t"
        "and          r10,        r27       \n\t"
        "eor          r11,        r10       \n\t"
        "mov          r10,        r7        \n\t"
        "and          r10,        r27       \n\t"
        "mov          r7,         r9        \n\t"
        "and          r7,         r27       \n\t"
        "swap         r7                    \n\t"
        "eor          r10,        r7        \n\t"
        "mov          r7,         r8        \n\t"
        "and          r7,         r5        \n\t"
        "mov          r8,         r6        \n\t"
        "and          r8,         r27       \n\t"
        "eor          r7,         r8        \n\t"
        "mov          r8,         r9        \n\t"
        "and          r8,         r5        \n\t"
        "swap         r6                    \n\t"
        "and          r6,         r27       \n\t"
        "eor          r8,         r6        \n\t"
        "mov          r9,         r7        \n\t"
        // Tweak2
        "movw         r6,         r20       \n\t"
        "movw         r20,        r16       \n\t"
        "movw         r16,        r22       \n\t"
        "movw         r22,        r18       \n\t"
        "mov          r19,        r7        \n\t"
        "and          r19,        r5        \n\t"
        "mov          r18,        r16       \n\t"
        "and          r18,        r27       \n\t"
        "eor          r19,        r18       \n\t"
        "mov          r18,        r7        \n\t"
        "and          r18,        r27       \n\t"
        "mov          r7,         r17       \n\t"
        "and          r7,         r27       \n\t"
        "swap         r7                    \n\t"
        "eor          r18,        r7        \n\t"
        "mov          r7,         r16       \n\t"
        "and          r7,         r5        \n\t"
        "mov          r16,        r6        \n\t"
        "and          r16,        r27       \n\t"
        "eor          r7,         r16       \n\t"
        "mov          r16,        r17       \n\t"
        "and          r16,        r5        \n\t"
        "swap         r6                    \n\t"
        "and          r6,         r27       \n\t"
        "eor          r16,        r6        \n\t"
        "mov          r17,        r7        \n\t"
        // LFSR
        "mov          r24,        r16       \n\t" // half of first row
        "mov          r25,        r24       \n\t"
        "lsr          r25                   \n\t"
        "eor          r24,        r25       \n\t"
        "lsr          r24                   \n\t"
        "lsr          r24                   \n\t"
        "andi         r24,        0x11      \n\t"
        "lsl          r16                   \n\t"
        "andi         r16,        0xee      \n\t"
        "eor          r16,        r24       \n\t"
        "mov          r24,        r17       \n\t" // half of first row
        "mov          r25,        r24       \n\t"
        "lsr          r25                   \n\t"
        "eor          r24,        r25       \n\t"
        "lsr          r24                   \n\t"
        "lsr          r24                   \n\t"
        "andi         r24,        0x11      \n\t"
        "lsl          r17                   \n\t"
        "andi         r17,        0xee      \n\t"
        "eor          r17,        r24       \n\t"
        "mov          r24,        r18       \n\t" // half of second row
        "mov          r25,        r24       \n\t"
        "lsr          r25                   \n\t"
        "eor          r24,        r25       \n\t"
        "lsr          r24                   \n\t"
        "lsr          r24                   \n\t"
        "andi         r24,        0x11      \n\t"
        "lsl          r18                   \n\t"
        "andi         r18,        0xee      \n\t"
        "eor          r18,        r24       \n\t"
        "mov          r24,        r19       \n\t" // half of second row
        "mov          r25,        r24       \n\t"
        "lsr          r25                   \n\t"
        "eor          r24,        r25       \n\t"
        "lsr          r24                   \n\t"
        "lsr          r24                   \n\t"
        "andi         r24,        0x11      \n\t"
        "lsl          r19                   \n\t"
        "andi         r19,        0xee      \n\t"
        "eor          r19,        r24       \n\t"
    "dec              r26                   \n\t"
    "breq             key_schedule_exit     \n\t"
    "rjmp             key_schedule_start    \n\t"
    "key_schedule_exit:                     \n\t"
        "pop          r29         \n\t"
        "pop          r28         \n\t"
        "pop          r17         \n\t"
        "pop          r16         \n\t"
        "pop          r15         \n\t"
        "pop          r14         \n\t"
        "pop          r13         \n\t"
        "pop          r12         \n\t"
        "pop          r11         \n\t"
        "pop          r10         \n\t"
        "pop          r9          \n\t"
        "pop          r8          \n\t"
        "pop          r7          \n\t"
        "pop          r6          \n\t"
        "pop          r5          \n\t"
        :
        : [key] "" (key), [roundKeys] "" (roundKeys), [RC] "" (RC));
}

#elif defined MSP
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    /* r4-r11  : key state                   */
    /* r12     : temp use                    */
    /* r13     : currentRound                */
    /* r14     : point to roundKeys          */
    /* r15     : point to key and RC         */
    asm volatile (
        /*
         * [r15-r12]: In MSPGCC, registers are passed starting with R15 and descending to R12.
         *     For example, if two integers are passed,
         *     the first is passed in R15 and the second is passed in R14.
         * [r11-r4]:  r11-r4 must be pushed if used.
         */
        "push         r4            \n\t"
        "push         r5            \n\t"
        "push         r6            \n\t"
        "push         r7            \n\t"
        "push         r8            \n\t"
        "push         r9            \n\t"
        "push         r10           \n\t"
        "push         r11           \n\t"
        // Load master keys
        "mov          @r15+,        r4            \n\t"
        "mov          @r15+,        r5            \n\t"
        "mov          @r15+,        r6            \n\t"
        "mov          @r15+,        r7            \n\t"
        "mov          @r15+,        r8            \n\t"
        "mov          @r15+,        r9            \n\t"
        "mov          @r15+,        r10           \n\t"
        "mov          @r15+,        r11           \n\t"
        "sub          #2,           r1            \n\t"
        "mov          %[RC],        r15           \n\t"
        "mov          #36,          r13           \n\t"
    "extend_loop:                                 \n\t"
        // AddRoundConstant
        "mov.b        @r15+,        r12           \n\t"
        "mov          r12,          0(r1)         \n\t"
        "and          #0x000f,      r12           \n\t"
        "rla          r12                         \n\t"
        "rla          r12                         \n\t"
        "rla          r12                         \n\t"
        "rla          r12                         \n\t"
        "xor          r4,           r12           \n\t"
        "xor          r8,           r12           \n\t"
        "mov          r12,          0(r14)        \n\t"
        "mov          0(r1),        r12           \n\t"
        "and          #0x0030,      r12           \n\t"
        "xor          r5,           r12           \n\t"
        "xor          r9,           r12           \n\t"
        "mov          r12,          2(r14)        \n\t"
        "add          #4,           r14           \n\t"
        // Permutation
        // r4 (k2  k3  k0  k1)          r4 (k8 k13  k9  k15)
        // r5 (k6  k7  k4  k5)          r5 (k12 k11 k10 k14)
        // r6 (k10 k11 k8  k9)   -----> r6 (k2  k3  k0  k1)
        // r7 (k14 k15 k12 k13)         r7 (k6  k7  k4  k5)
        "mov          r13,          0(r1)         \n\t"
        // Tweak1 -- First row
        "mov          r6,           r12           \n\t"
        "mov          r4,           r6            \n\t"
        "mov          r7,           r4            \n\t"
        "mov          r5,           r7            \n\t"
        "swpb         r4                          \n\t"
        "mov          r4,           r13           \n\t"
        "and          #0x0f0f,      r4            \n\t"
        "mov          r12,          r5            \n\t"
        "rla          r5                          \n\t"
        "rla          r5                          \n\t"
        "rla          r5                          \n\t"
        "rla          r5                          \n\t"
        "and          #0xf0,        r5            \n\t"
        "xor          r5,           r4            \n\t"
        "mov          r12,          r5            \n\t"
        "swpb         r5                          \n\t"
        "and          #0xf000,      r5            \n\t"
        "xor          r5,           r4            \n\t"
        // Tweak1 -- Second row
        "mov          r12,          r5            \n\t"
        "and          #0x0f00,      r5            \n\t"
        "swpb         r12                         \n\t"
        "and          #0xf0,        r12           \n\t"
        "xor          r12,          r5            \n\t"
        "mov          r13,          r12           \n\t"
        "rra          r12                         \n\t"
        "rra          r12                         \n\t"
        "rra          r12                         \n\t"
        "rra          r12                         \n\t"
        "and          #0xf,         r12           \n\t"
        "xor          r12,          r5            \n\t"
        "and          #0xf000,      r13           \n\t"
        "xor          r13,          r5            \n\t"
        // Tweak2 -- First row
        "mov          r10,          r12           \n\t"
        "mov          r8,           r10           \n\t"
        "mov          r11,          r8            \n\t"
        "mov          r9,           r11           \n\t"
        "swpb         r8                          \n\t"
        "mov          r8,           r13           \n\t"
        "and          #0x0f0f,      r8            \n\t"
        "mov          r12,          r9            \n\t"
        "rla          r9                          \n\t"
        "rla          r9                          \n\t"
        "rla          r9                          \n\t"
        "rla          r9                          \n\t"
        "and          #0xf0,        r9            \n\t"
        "xor          r9,           r8            \n\t"
        "mov          r12,          r9            \n\t"
        "swpb         r9                          \n\t"
        "and          #0xf000,      r9            \n\t"
        "xor          r9,           r8            \n\t"
        // Tweak2 -- Second row
        "mov          r12,          r9            \n\t"
        "and          #0x0f00,      r9            \n\t"
        "swpb         r12                         \n\t"
        "and          #0xf0,        r12           \n\t"
        "xor          r12,          r9            \n\t"
        "mov          r13,          r12           \n\t"
        "rra          r12                         \n\t"
        "rra          r12                         \n\t"
        "rra          r12                         \n\t"
        "rra          r12                         \n\t"
        "and          #0xf,         r12           \n\t"
        "xor          r12,          r9            \n\t"
        "and          #0xf000,      r13           \n\t"
        "xor          r13,          r9            \n\t"
        // LFSR -- Tweak2 First row
        "mov          r8,           r12           \n\t"
        "mov          r8,           r13           \n\t"
        "rra          r13                         \n\t"
        "xor          r12,          r13           \n\t"
        "rra          r13                         \n\t"
        "rra          r13                         \n\t"
        "and          #0x1111,      r13           \n\t"
        "rla          r8                          \n\t"
        "and          #0xeeee,      r8            \n\t"
        "xor          r13,          r8            \n\t"
        // LFSR -- Tweak2 Second row
        "mov          r9,           r12           \n\t"
        "mov          r9,           r13           \n\t"
        "rra          r13                         \n\t"
        "xor          r12,          r13           \n\t"
        "rra          r13                         \n\t"
        "rra          r13                         \n\t"
        "and          #0x1111,      r13           \n\t"
        "rla          r9                          \n\t"
        "and          #0xeeee,      r9            \n\t"
        "xor          r13,          r9            \n\t"
        // Loop control
        "mov          0(r1),        r13           \n\t"
    "dec              r13                         \n\t"
    "jne              extend_loop                 \n\t"
        "add          #2,           r1            \n\t"
        /* ----------------------------------------- */
        "pop          r11           \n\t"
        "pop          r10           \n\t"
        "pop          r9            \n\t"
        "pop          r8            \n\t"
        "pop          r7            \n\t"
        "pop          r6            \n\t"
        "pop          r5            \n\t"
        "pop          r4            \n\t"    
    :
    : [key] "m" (key), [roundKeys] "m" (roundKeys), [RC] "" (RC));
}

#elif defined ARM
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    // r0    : ponits to key
    // r1    : points to roundKeys
    // r2-r5 : key state
    // r6-r7 : temp use
    // r8    : loop control
    // r9    : points to RC
    // r10   : 0xf00f0
    // r11   : 0xf00f0f
    asm volatile(
        "stmdb      sp!,      {r2-r11}        \n\t"
        "mov        r8,       #36             \n\t"
        "ldr        r9,       =RC             \n\t"
        "mov        r10,      #0xf            \n\t"
        "lsl        r10,      #16             \n\t"
        "eors       r10,      r10, #0xf0      \n\t"
        "mov        r11,      r10, lsl #4     \n\t"
        "eors       r11,      r11, #0xf       \n\t"
        "ldmia      r0,       {r2-r5}         \n\t" // load master key
    "key_loop:                                \n\t"
        "ldrb       r6,       [r9]            \n\t"
        "adds       r9,       r9, #1          \n\t"
        "mov        r7,       r6, lsl #16     \n\t"
        "and        r6,       r6, #0xf        \n\t"
        "eors       r6,       r2, r6, lsl #4  \n\t"
        "and        r7,       r7, #0x300000  \n\t"
        "eors       r6,       r6, r7         \n\t"
        "eors       r6,       r6, r4          \n\t"
        "str        r6,       [r1,#0]         \n\t" // store round keys
        "adds       r1,       r1, #4          \n\t"
        // Permutation
        // r2(k6  k7  k4  k5  k2  k3  k0  k1)    k12 k11 k10 k14 k8  k13 k9 k15
        // r3(k14 k15 k12 k13 k10 k11 k8  k9) -> k6  k7  k4  k5  k2  k3  k0  k1
        // Tweak1
        "mov        r6,       r3              \n\t" 
        "mov        r3,       r2              \n\t"
        "rev        r2,       r6              \n\t"
        "ands       r2,       r2, r11         \n\t"
        "mov        r7,       r6, lsl #8      \n\t"
        "and        r7,       r7, #0xf000f000 \n\t"
        "eors       r2,       r2, r7          \n\t"
        "rev16      r7,       r6              \n\t"
        "and        r7,       r10, r7, lsr #4 \n\t"
        "eors       r2,       r2, r7          \n\t"
        "and        r6,       r6, #0xf00      \n\t"
        "eors       r2,       r2, r6, lsl #16 \n\t"
        // Tweak2
        "mov        r6,       r5              \n\t" 
        "mov        r5,       r4              \n\t"
        "rev        r4,       r6              \n\t"
        "ands       r4,       r4, r11         \n\t"
        "mov        r7,       r6, lsl #8      \n\t"
        "and        r7,       r7, #0xf000f000 \n\t"
        "eors       r4,       r4, r7          \n\t"
        "rev16      r7,       r6              \n\t"
        "and        r7,       r10, r7, lsr #4 \n\t"
        "eors       r4,       r4, r7          \n\t"
        "and        r6,       r6, #0xf00      \n\t"
        "eors       r4,       r4, r6, lsl #16 \n\t"
        // LFSR -- Tweak2
        "mov        r6,       r4              \n\t"
        "mov        r7,       r4              \n\t"
        "eor        r6,       r6, r7, lsr #1  \n\t"
        "lsr        r6,       #2              \n\t"
        "and        r6,       r6, #0x11111111 \n\t"
        "lsl        r4,       #1              \n\t"
        "and        r4,       r4, #0xeeeeeeee \n\t"
        "eors       r4,       r4, r6          \n\t"
    "subs           r8,       r8, #1          \n\t"
    "bne            key_loop                  \n\t"
        "ldmia      sp!,      {r2-r11}        \n\t"
    :
    : [key] "r" (key), [roundKeys] "r" (roundKeys), [RC] "" (RC));
}

#else
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    /* Add here the cipher encryption key schedule implementation */
}

#endif

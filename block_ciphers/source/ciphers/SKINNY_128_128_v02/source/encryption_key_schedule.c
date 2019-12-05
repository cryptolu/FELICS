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
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    /*--------------------------------------*/
    // Round keys and round constants are eor-ed
    // and stored together
    /* r5-r6   : tk0, tk4                   */
    /* r7-r22  : master keys                */
    /* r23     : loop control               */
    /* r24-r25 : temp use                   */
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
        "ldi          r23,        40        \n\t"
        // load_keys
        // r7  r8  r9  r10
        // r11 r12 r13 r14
        // r15 r16 r17 r18
        // r19 r20 r21 r22
        "ld           r7,         x+        \n\t"
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
        "ldi          r30,        lo8(RC)   \n\t"
        "ldi          r31,        hi8(RC)   \n\t"
    "key_schedule_start:                    \n\t"
        // add round const
        "lpm          r24,        z+        \n\t"
        "mov          r25,        r24       \n\t"
        "andi         r25,        0x0f      \n\t"
        "mov          r5,         r7        \n\t"
        "eor          r5,         r25       \n\t"
        "andi         r24,        0x30      \n\t"
        "swap         r24                   \n\t"
        "mov          r6,         r11       \n\t"
        "eor          r6,         r24       \n\t"
        // store round keys
        "st           y+,         r5        \n\t"
        "st           y+,         r8        \n\t"
        "st           y+,         r9        \n\t"
        "st           y+,         r10       \n\t"
        "st           y+,         r6        \n\t"
        "st           y+,         r12       \n\t"
        "st           y+,         r13       \n\t"
        "st           y+,         r14       \n\t"
    "dec              r23                   \n\t"
    "breq             key_schedule_exit     \n\t"
        // k0  k1  k2  k3         k9  k15 k8  k13
        // k4  k5  k6  k7         k10 k14 k12 k11
        // k8  k9  k10 k11 -----> k0  k1  k2  k3
        // k12 k13 k14 k15        k4  k5  k6  k7
        // some instructions can be deleted with the use of movw
        "mov          r24,        r7        \n\t"
        "mov          r7,         r16       \n\t"
        "mov          r16,        r8        \n\t"
        "mov          r8,         r22       \n\t"
        "mov          r22,        r14       \n\t"
        "mov          r14,        r18       \n\t"
        "mov          r18,        r10       \n\t"
        "mov          r10,        r20       \n\t"
        "mov          r20,        r12       \n\t"
        "mov          r12,        r21       \n\t"
        "mov          r21,        r13       \n\t"
        "mov          r13,        r19       \n\t"
        "mov          r19,        r11       \n\t"
        "mov          r11,        r17       \n\t"
        "mov          r17,        r9        \n\t"
        "mov          r9,         r15       \n\t"
        "mov          r15,        r24       \n\t"
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
        // k0  k1  k2  k3         k9  k15 k8  k13
        // k4  k5  k6  k7         k10 k14 k12 k11
        // k8  k9  k10 k11 -----> k0  k1  k2  k3
        // k12 k13 k14 k15        k4  k5  k6  k7
        // r4 (k1  k0)  r5 (k3  k2)
        // r6 (k5  k4)  r7 (k7  k6)
        // r8 (k9  k8)  r9 (k11 k10)
        // r10(k13 k12) r11(k15 k14)
        "mov          @r15+,        r4            \n\t"
        "mov          @r15+,        r5            \n\t"
        "mov          @r15+,        r6            \n\t"
        "mov          @r15+,        r7            \n\t"
        "mov          @r15+,        r8            \n\t"
        "mov          @r15+,        r9            \n\t"
        "mov          @r15+,        r10           \n\t"
        "mov          @r15+,        r11           \n\t"
        "sub          #8,           r1            \n\t"
        "mov          %[RC],        r15           \n\t"
        "mov          #40,          r13           \n\t"
    "extend_loop:                                 \n\t"
        // load round const
        "mov.b        @r15+,        r12           \n\t"
        "mov          r12,          0(r1)         \n\t"
        // k0 eor
        "and          #0x000f,      r12           \n\t"
        "xor          r4,           r12           \n\t"
        // store the first 4 bytes
        "mov          r12,          0(r14)        \n\t"
        "mov          r5,           2(r14)        \n\t"
        // k4 eor
        "mov          0(r1),        r12           \n\t"
        "and          #0x0030,      r12           \n\t"
        "rra          r12                         \n\t"
        "rra          r12                         \n\t"
        "rra          r12                         \n\t"
        "rra          r12                         \n\t"
        "xor          r6,           r12           \n\t"
        // store the second 4 bytes
        "mov          r12,          4(r14)        \n\t"
        "mov          r7,           6(r14)        \n\t"
        "add          #8,           r14           \n\t"
        // state change
        // r4 (k1  k0)  r5 (k3  k2)         r4 (k15 k9)  r5 (k13 k8)
        // r6 (k5  k4)  r7 (k7  k6)         r6 (k14 k10) r7 (k11 k12)
        // r8 (k9  k8)  r9 (k11 k10) -----> r8 (k1  k0)  r9 (k3  k2)
        // r10(k13 k12) r11(k15 k14)        r10(k5  k4)  r11(k7  k6)
        "mov          r8,           0(r1)         \n\t"
        "mov          r9,           2(r1)         \n\t"
        "mov          r10,          4(r1)         \n\t"
        "mov          r11,          6(r1)         \n\t"
        "mov          r4,           r8            \n\t"
        "mov          r5,           r9            \n\t"
        "mov          r6,           r10           \n\t"
        "mov          r7,           r11           \n\t"
        "mov          0(r1),        r4            \n\t"
        "mov.b        r4,           r5            \n\t"
        "swpb         r4                          \n\t"
        "and          #0x00ff,      r4            \n\t"
        "mov          6(r1),        r12           \n\t"
        "mov.b        r12,          r6            \n\t"
        "and          #0xff00,      r12           \n\t"
        "xor          r12,          r4            \n\t"
        "swpb         r6                          \n\t"
        "mov          4(r1),        r12           \n\t"
        "mov.b        r12,          r7            \n\t"
        "and          #0xff00,      r12           \n\t"
        "xor          r12,          r5            \n\t"
        "mov          2(r1),        r12           \n\t"
        "and          #0xff00,      r12           \n\t"
        "xor          r12,          r7            \n\t"
        "mov          2(r1),        r12           \n\t"
        "and          #0x00ff,      r12           \n\t"
        "xor          r12,          r6            \n\t"
        "dec          r13                         \n\t"
        "jne          extend_loop                 \n\t"
        "add          #8,           r1            \n\t"
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
    asm volatile(
        "stmdb      sp!,      {r2-r9}         \n\t"
        "mov        r8,       #40             \n\t"
        "ldr        r9,       =RC             \n\t"
        "ldmia      r0,       {r2-r5}         \n\t" // load master key
    "key_loop:                                \n\t"
        "ldrb       r6,       [r9]            \n\t"
        "adds       r9,       r9, #1          \n\t"
        "eors       r7,       r3, r6, lsr #4  \n\t" // k4^rc
        "ands       r6,       r6, #0xf        \n\t"
        "eors       r6,       r6, r2          \n\t" // k0^rc
        "strd       r6,r7,    [r1,#0]         \n\t" // store round keys
        "adds       r1,       r1, #8          \n\t"
        // r2 (k3  k2  k1  k0)         k13 k8  k15 k9
        // r3 (k7  k6  k5  k4)         k11 k12 k14 k10
        // r4 (k11 k10 k9  k8) ------> k3  k2  k1  k0
        // r5 (k15 k14 k13 k12)        k7  k6  k5  k4
        "mov        r6,       r4              \n\t" // r6 = (k11 k10 k9  k8 )
        "mov        r7,       r5              \n\t" // r7 = (k15 k14 k13 k12)
        "mov        r4,       r2              \n\t" // r4 = (k3  k2  k1  k0)
        "mov        r5,       r3              \n\t" // r5 = (k7  k6  k5  k4)
        "rev        r2,       r7              \n\t" // r2 = (k12 k13 k14 k15)
        "lsls       r2,       r2, #8          \n\t" // r2 = (k13 k14 k15 --)
        "bfi        r2,r6,    #16,#8          \n\t" // r2 = (k13 k8  k15 --)
        "lsrs       r6,       r6, #8          \n\t" // r6 = ( -- k11 k10 k9)
        "bfi        r2,r6,    #0, #8          \n\t" // r2 = (k13 k8  k15 k9)
        "rev16      r3,       r6              \n\t" // r3 = (k11 --  k9  k10)
        "bfi        r3,r7,    #16,#8          \n\t" // r3 = (k11 k12 k9  k10)
        "lsrs       r7,       r7, #16         \n\t" // r7 = (--  --  k15 k14)
        "bfi        r3,r7,    #8, #8          \n\t" // r3 = (k11 k12 k14 k10)
    "subs           r8,       r8, #1          \n\t"
    "bne            key_loop                  \n\t"
        "ldmia      sp!,      {r2-r9}         \n\t"
    :
    : [key] "r" (key), [roundKeys] "r" (roundKeys), [RC] "" (RC));
}

#else
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    /* Add here the cipher encryption key schedule implementation */
}

#endif

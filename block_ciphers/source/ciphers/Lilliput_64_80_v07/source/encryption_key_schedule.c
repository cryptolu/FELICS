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
#include <string.h>

#include "cipher.h"
#include "constants.h"


#ifdef AVR
/*----------------------------------------------------------------------------*/
/* Optimized for AVR                                                          */
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    asm volatile (\
        /*--------------------------------------------------*/
        /* Registers allocation:                            */
        /*     r0-r19  : state                              */
        /*     r20     : loop counter                       */
        /*     r21     : temporary 0 / RK                   */
        /*     r22     : temporary 1                        */
        /*     r23     : temporary 2 / RK                   */
        /*     r24     : temporary 3 / RK                   */
        /*     r25     : RK                                 */
        /*     r26     : RK                                 */
        /*     r27     : RK                                 */
        /*     r28     : RK                                 */
        /*     r29     : RK                                 */
        /*     r30:r31 : Z Key / Sbox                       */
        /*--------------------------------------------------*/
        /* Store all modified registers */
        /*--------------------------------------------------*/
        "push  r0;\n"
        "push  r1;\n"
        "push  r2;\n"
        "push  r3;\n"
        "push  r4;\n"
        "push  r5;\n"
        "push  r6;\n"
        "push  r7;\n"
        "push  r8;\n"
        "push  r9;\n"
        "push r10;\n"
        "push r11;\n"
        "push r12;\n"
        "push r13;\n"
        "push r14;\n"
        "push r15;\n"
        "push r16;\n"
        "push r17;\n"
       	
        /*--------------------------------------------------*/
        /* copy the block state from memory to registers    */
        /*--------------------------------------------------*/
        "ld    r0,    x+;\n"
        "ld    r1,    x+;\n"
        "ld    r2,    x+;\n"
        "ld    r3,    x+;\n"
        "ld    r4,    x+;\n"
        "ld    r5,    x+;\n"
        "ld    r6,    x+;\n"
        "ld    r7,    x+;\n"
        "ld    r8,    x+;\n"
        "ld    r9,    x+;\n"
        "ld   r10,    x+;\n"
        "ld   r11,    x+;\n"
        "ld   r12,    x+;\n"
        "ld   r13,    x+;\n"
        "ld   r14,    x+;\n"
        "ld   r15,    x+;\n"
        "ld   r16,    x+;\n"
        "ld   r17,    x+;\n"
        "ld   r18,    x+;\n"
        "ld   r19,    x+;\n"
        /*--------------------------------------------------*/
        
        "ldi  r20,    30;\n" /* 30 rounds */
"key_schedule_round:          \n"
        /*--------------------------------------------------*/
        /*	Extract RK										*/
        /*--------------------------------------------------*/
		"mov   r21,    r16;\n" /* roundKeys[i*8 + 0] =  ((uint8_t)( ((tmpKey[16] & 0x1)<<3) | ((tmpKey[10] & 0x1)<<2) | ((tmpKey[6] & 0x1)<<1) | ((tmpKey[1] & 0x1)) ) ); */
		"andi   r21,    0x01;\n"
		"lsl   r21;\n"
		"lsl   r21;\n"
		"lsl   r21;\n"
		
		"mov   r22,    r10;\n"
		"andi   r22,    0x01;\n"
		"lsl   r22;\n"
		"lsl   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r22,    r6;\n"
		"andi   r22,    0x01;\n"
		"lsl   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r22,    r1;\n"
		"andi   r22,    0x01;\n"
		"or   r21,    r22;\n"
		
		"mov   r23,    r21;\n" /*RK[0] */
		
		
		"mov   r21,    r16;\n" /* roundKeys[i*8 + 1] = ( (uint8_t)( ((tmpKey[16] & 0x2)<<2) | ((tmpKey[10] & 0x2)<<1) | ((tmpKey[6] & 0x2)) | ((tmpKey[1] & 0x2)>>1) ) ) ; */
		"andi   r21,     0x02;\n"
		"lsl   r21;\n"
		"lsl   r21;\n"
		
		"mov   r22,    r10;\n"
		"andi   r22,     0x02;\n"
		"lsl   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r22,    r6;\n"
		"andi   r22,     0x02;\n"
		"or   r21,    r22;\n"
		
		"mov   r22,    r1;\n"
		"andi   r22,     0x02;\n"
		"lsr   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r24,    r21;\n" /*RK[1] */
		
		
		"mov   r21,    r16;\n"
		"andi   r21,     0x04;\n"
		"lsl   r21;\n"
		
		"mov   r22,    r10;\n"
		"andi   r22,     0x04;\n"
		"or   r21,    r22;\n"
		
		"mov   r22,    r6;\n"
		"andi   r22,     0x04;\n"
		"lsr   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r22,    r1;\n"
		"andi   r22,     0x04;\n"
		"lsr   r22;\n"
		"lsr   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r25,    r21;\n" /*RK[2] */
		
		
		"mov   r21,    r16;\n"
		"andi   r21,     0x08;\n"
		
		"mov   r22,    r10;\n"
		"andi   r22,     0x08;\n"
		"lsr   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r22,    r6;\n"
		"andi   r22,     0x08;\n"
		"lsr   r22;\n"
		"lsr   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r22,    r1;\n"
		"andi   r22,     0x08;\n"
		"lsr   r22;\n"
		"lsr   r22;\n"
		"lsr   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r26,    r21;\n" /*RK[3] */
		
		
		/*--------------------------------------------------*/
		"mov   r21,    r18;\n" /* roundKeys[i*8 + 4] = ( (uint8_t)( ((tmpKey[18] & 0x1)<<3) | ((tmpKey[13] & 0x1)<<2) | ((tmpKey[9] & 0x1)<<1) | ((tmpKey[3] & 0x1)) )  ) ; */
		"andi   r21,     0x01;\n"
		"lsl   r21;\n"
		"lsl   r21;\n"
		"lsl   r21;\n"
		
		"mov   r22,    r13;\n"
		"andi   r22,     0x01;\n"
		"lsl   r22;\n"
		"lsl   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r22,    r9;\n"
		"andi   r22,     0x01;\n"
		"lsl   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r22,    r3;\n"
		"andi   r22,     0x01;\n"
		"or   r21,    r22;\n"
		
		"mov   r27,    r21;\n" /*RK[4] */
		
		
		"mov   r21,    r18;\n"
		"andi   r21,     0x02;\n"
		"lsl   r21;\n"
		"lsl   r21;\n"
		
		"mov   r22,    r13;\n"
		"andi   r22,     0x02;\n"
		"lsl   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r22,    r9;\n"
		"andi   r22,     0x02;\n"
		"or   r21,    r22;\n"
		
		"mov   r22,    r3;\n"
		"andi   r22,     0x02;\n"
		"lsr   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r28,    r21;\n" /*RK[5] */
		
		
		"mov   r21,    r18;\n"
		"andi   r21,     0x04;\n"
		"lsl   r21;\n"
		
		"mov   r22,    r13;\n"
		"andi   r22,     0x04;\n"
		"or   r21,    r22;\n"
		
		"mov   r22,    r9;\n"
		"andi   r22,     0x04;\n"
		"lsr   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r22,    r3;\n"
		"andi   r22,     0x04;\n"
		"lsr   r22;\n"
		"lsr   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r29,    r21;\n" /*RK[6] */
		

		"mov   r21,    r18;\n"
		"andi   r21,     0x08;\n"
		
		"mov   r22,    r13;\n"
		"andi   r22,     0x08;\n"
		"lsr   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r22,    r9;\n"
		"andi   r22,     0x08;\n"
		"lsr   r22;\n"
		"lsr   r22;\n"
		"or   r21,    r22;\n"
		
		"mov   r22,    r3;\n"
		"andi   r22,     0x08;\n"
		"lsr   r22;\n"
		"lsr   r22;\n"
		"lsr   r22;\n"
		"or   r21,    r22;\n" /*RK[7] */
		
		
		
		/*--------------------------------------------------*/
        /* SBOX 											*/
        /*--------------------------------------------------*/
        "push r30;       \n" /* push z                      */ 
        "push r31;       \n"
        "ldi  r30,   lo8(S);\n" /* Load Sbox*/
        "ldi  r31,   hi8(S);\n"
        
        
        "mov  r30,    r23;\n" 
        "ldi r31, 0;\n"
        "subi r30, lo8(-(S))  ;\n" /* Load Sbox(r23 = RK[0])*/
        "sbci r31, hi8(-(S))  ;\n"
        "lpm r23, Z;\n" /* store sbox(r23) */
        
        "mov  r30,    r24;\n"
        "ldi r31, 0;\n"
        "subi r30, lo8(-(S))  ;\n"
        "sbci r31, hi8(-(S))  ;\n"
        "lpm r24, Z;\n"
        
        "mov  r30,    r25;\n"
        "ldi r31, 0;\n"
        "subi r30, lo8(-(S))  ;\n"
        "sbci r31, hi8(-(S))  ;\n"
        "lpm r25, Z;\n"
        
        "mov  r30,    r26;\n"
        "ldi r31, 0;\n"
        "subi r30, lo8(-(S))  ;\n"
        "sbci r31, hi8(-(S))  ;\n"
        "lpm r26, Z;\n"
        
        "mov  r30,    r27;\n"
        "ldi r31, 0;\n"
        "subi r30, lo8(-(S))  ;\n"
        "sbci r31, hi8(-(S))  ;\n"
        "lpm r27, Z;\n"
        
        "mov  r30,    r28;\n"
        "ldi r31, 0;\n"
        "subi r30, lo8(-(S))  ;\n"
        "sbci r31, hi8(-(S))  ;\n"
        "lpm r28, Z;\n"
        
        "mov  r30,    r29;\n"
        "ldi r31, 0;\n"
        "subi r30, lo8(-(S))  ;\n"
        "sbci r31, hi8(-(S))  ;\n"
        "lpm r29, Z;\n"
        
        "mov  r30,    r21;\n"
        "ldi r31, 0;\n"
        "subi r30, lo8(-(S))  ;\n"
        "sbci r31, hi8(-(S))  ;\n"
        "lpm r21, Z;\n"
		
		
		"pop  r31;       \n"
        "pop  r30;       \n"
        
        
		/*--------------------------------------------------*/
        "st  z+,    r23;\n" /* store RK[0]*/
        "st  z+,    r24;\n"
        "st  z+,    r25;\n"
        "st  z+,    r26;\n"
        "st  z+,    r27;\n"
        "st  z+,    r28;\n" /* store RK[5]*/
        
        /*--------------------------------------------------*/
        "ldi  r23,    0x1e;\n" /* XOR RK[6] and RK[7] with number of round */
        "sub  r23,    r20;\n"
        "mov  r24,    r23;\n"
        "lsl   r23;\n"
        "lsl   r23;\n"
        "lsl   r23;\n"
        "lsl   r23;\n"
        "lsl   r23;\n"
        "lsl   r23;\n"
        "lsl   r23;\n"
        "andi  r23,    0x80;\n"
        "lsr   r24;\n"
        "andi  r24,    0x0f;\n"
        "eor  r23,    r24;\n"
        "mov  r24,    r23;\n"
        "andi  r23,    0x0f;\n"
        "eor  r21,    r23;\n"
        
        "andi  r24,    0xf0;\n"
        "lsr   r24;\n"
        "lsr   r24;\n"
        "lsr   r24;\n"
        "lsr   r24;\n"
        "eor  r29,    r24;\n"
        
		
        "st  z+,    r29;\n" /* store RK[6]*/
        "st  z+,    r21;\n"/* store RK[7]*/
        
        /*--------------------------------------------------*/
        "dec  r20;       \n"
        
        "brne key_schedule_permutation;\n"
        "jmp  key_schedule_final_round;\n"
        
        /*--------------------------------------------------*/
        /* Mixing LFSM + Permutation LFSM                   */
        /*--------------------------------------------------*/
"key_schedule_permutation:\n" 
		
		"mov  r21,    r0;\n" /* 1st lfsr - temp = tmpKey[0] ;*/
		"mov  r0,    r4;\n" /* tmpKey[0] = tmpKey[4]; */
		"mov  r4,    r3;\n" /* tmpKey[4] = tmpKey[3]; */
		"mov  r3,    r2;\n" /* tmpKey[3] = tmpKey[2]; */
		"lsr   r2;\n" /* tmpKey[2] = tmpKey[1] ^ (tmpKey[2]>>3); */
		"lsr   r2;\n"
		"lsr   r2;\n"
		"eor  r2,    r1;\n"
		"mov  r22,    r0;\n" /* tmpKey[1] = temp ^ (tmpKey[0]>>1) ^ ( (tmpKey[0]<<3) & 0x0f); */
		"lsr   r22;\n"
		"mov  r23,    r0;\n"
		"lsl   r23;\n"
		"lsl   r23;\n"
		"lsl   r23;\n"
		"andi  r23,    0x0f;\n"
		"eor  r22,    r23;\n"
		"eor  r22,    r21;\n"
		"mov  r1,    r22;\n"
		
		/*--------------------------------------------------*/
		"mov  r21,    r5;\n"/* 2nd lfsr*/
		"mov  r22,    r8;\n"
		"lsl   r22;\n"
		"andi  r22,    0x0f;\n"
		"mov  r23,    r8;\n"
		"lsr   r23;\n"
		"lsr   r23;\n"
		"lsr   r23;\n"
		"eor  r22,    r23;\n"
		"eor  r22,    r9;\n"
		"mov  r5,    r22;\n"
		"mov  r9,    r8;\n"
		"mov  r8,    r7;\n"
		"mov  r22,    r7;\n"
		"lsl   r22;\n"
		"lsl   r22;\n"
		"lsl   r22;\n"
		"andi  r22,    0x0f;\n"
		"eor  r22,    r6;\n"
		"mov  r7,    r22;\n"
		"mov  r6,    r21;\n"
		
		/*--------------------------------------------------*/
		"mov  r21,    r10;\n"/* 3rd lfsr*/
		"mov  r10,    r14;\n"
		"mov  r22,    r12;\n"
		"lsr   r22;\n"
		"lsr   r22;\n"
		"lsr   r22;\n"
		"eor  r22,    r13;\n"
		"mov  r14,    r22;\n"
		"mov  r13,    r12;\n"
		"mov  r22,    r12;\n"
		"lsr   r22;\n"
		"mov  r23,    r12;\n"
		"lsl   r23;\n"
		"lsl   r23;\n"
		"lsl   r23;\n"
		"andi  r23,    0x0f;\n"
		"eor  r22,    r23;\n"
		"eor  r22,    r11;\n"
		"mov  r12,    r22;\n"
		"mov  r11,    r21;\n"
		
		/*--------------------------------------------------*/
		"mov  r21,    r15;\n"/* 4th lfsr*/
		"mov  r15,    r19;\n"
		"mov  r19,    r18;\n"
		"mov  r18,    r17;\n"
		"mov  r22,    r17;\n"
		"lsl   r22;\n"
		"andi  r22,    0x0f;\n"
		"lsr   r17;\n"
		"lsr   r17;\n"
		"lsr   r17;\n"
		"mov  r23,    r21;\n"
		"lsl   r23;\n"
		"lsl   r23;\n"
		"lsl   r23;\n"
		"andi  r23,    0x0f;\n"
		"eor  r22,    r23;\n"
		"eor  r17,    r22;\n"
		"eor  r17,    r16;\n"
		"mov  r16,    r21;\n"
		
		
		"jmp key_schedule_round;\n"


		/*--------------------------------------------------*/
"key_schedule_final_round:\n"


		
        /*--------------------------------------------------*/
        /* Restore all modified registers                   */
        /*--------------------------------------------------*/
		"pop  r17;\n"
        "pop  r16;\n"
        "pop  r15;\n"
        "pop  r14;\n"
        "pop  r13;\n"
        "pop  r12;\n"
        "pop  r11;\n"
        "pop  r10;\n"
        "pop   r9;\n"
        "pop   r8;\n"
        "pop   r7;\n"
        "pop   r6;\n"
        "pop   r5;\n"
        "pop   r4;\n"
        "pop   r3;\n"
        "pop   r2;\n"
        "pop   r1;\n" 
        "pop   r0;\n"
        /*--------------------------------------------------*/
    :
    : [key] "x" (key), [roundKeys] "z" (roundKeys), [S] "" (S)); 
}



#else

/*----------------------------------------------------------------------------*/
/* Optimized for MSP                                                          */
/*----------------------------------------------------------------------------*/
#ifdef MSP
/*----------------------------------------------------------------------------*/
/* Assembly                                                                   */
/*----------------------------------------------------------------------------*/
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    asm volatile (\
        /*--------------------------------------------------*/
        /* r0-r19  - Key                                    */
        /* r20  - key                                       */
        /* r21 - RoundKeys                                  */
        /* r22 - counter                                    */
        /* r25 - RoundKeys                                  */
        /*--------------------------------------------------*/
        /* Store all modified registers                     */
        /*--------------------------------------------------*/
        "push   r5;                 \n"
        "push   r6;                 \n"
        "push   r7;                 \n"
        "push   r8;                 \n"
        "push   r9;                 \n"
        "push   r10;                \n"
        "push   r11;                \n"
        "push   r12;                \n"
        "push   r13;                \n"
        "push   r14;                \n"
        "push   r15;                \n"
        
        /*--------------------------------------------------*/
        "mov    %[key],         r15;\n"
        "mov    %[roundKeys],   r14;\n"
        
        
        /*---------------------------------------------------------------*/
		/* Save Initial Key                                              */
        /*---------------------------------------------------------------*/
        "push   0(r15);                \n"
        "push   1(r15);                \n"
        "push   2(r15);                \n"
        "push   3(r15);                \n"
        "push   4(r15);                \n"
        "push   5(r15);                \n"
        "push   6(r15);                \n"
        "push   7(r15);                \n"
        "push   8(r15);                \n"
        "push   9(r15);                \n"
        "push   10(r15);                \n"
        "push   11(r15);                \n"
        "push   12(r15);                \n"
        "push   13(r15);                \n"
        "push   14(r15);                \n"
        "push   15(r15);                \n"
        "push   16(r15);                \n"
        "push   17(r15);                \n"
        "push   18(r15);                \n"
        "push   19(r15);                \n"
        
        /*--------------------------------------------------*/
        "mov    #30,            r11;\n" /* 30 rounds */
        
"key_schedule_round_loop:                \n"

		/*---------------------------------------------------------------*/
		/* Extract Round Key                                             */
        /*---------------------------------------------------------------*/
		"mov.b    16(r15),            r12;\n" /* roundKeys[i*8 + 0] =  ((uint8_t)( ((tmpKey[16] & 0x1)<<3) | ((tmpKey[10] & 0x1)<<2) | ((tmpKey[6] & 0x1)<<1) | ((tmpKey[1] & 0x1)) ) ); */
		"and.b  #1,           r12;\n" 
		"rla.b  r12;\n"
		"rla.b  r12;\n"
		"rla.b  r12;\n"
		
		"mov.b    10(r15),            r13;\n"
		"and.b  #1,           r13;\n" 
		"rla.b  r13;\n"
		"rla.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    6(r15),            r13;\n"
		"and.b  #1,           r13;\n" 
		"rla.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    1(r15),            r13;\n"
		"and.b  #1,           r13;\n" 
		"bis.b  r13,           r12;\n" 
		
		"mov.b    r12,             0(r14);\n"
		
		
		
		"mov.b    16(r15),            r12;\n" /* roundKeys[i*8 + 1] = ( (uint8_t)( ((tmpKey[16] & 0x2)<<2) | ((tmpKey[10] & 0x2)<<1) | ((tmpKey[6] & 0x2)) | ((tmpKey[1] & 0x2)>>1) ) )  ;  */
		"and.b  #2,           r12;\n" 
		"rla.b  r12;\n"
		"rla.b  r12;\n"
		
		"mov.b    10(r15),            r13;\n"
		"and.b  #2,           r13;\n" 
		"rla.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    6(r15),            r13;\n"
		"and.b  #2,           r13;\n" 
		"bis.b  r13,           r12;\n" 
		
		"mov.b    1(r15),            r13;\n"
		"and.b  #2,           r13;\n" 
		"rra.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    r12,             1(r14);\n"
		
		
		
		"mov.b    16(r15),            r12;\n"
		"and.b  #4,           r12;\n" 
		"rla.b  r12;\n"
		
		"mov.b    10(r15),            r13;\n"
		"and.b  #4,           r13;\n" 
		"bis.b  r13,           r12;\n" 
		
		"mov.b    6(r15),            r13;\n"
		"and.b  #4,           r13;\n"
		"rra.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    1(r15),            r13;\n"
		"and.b  #4,           r13;\n" 
		"rra.b  r13;\n"
		"rra.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    r12,             2(r14);\n"
		
		
		
		"mov.b    16(r15),            r12;\n"
		"and.b  #8,           r12;\n" 
				
		"mov.b    10(r15),            r13;\n"
		"and.b  #8,           r13;\n" 
		"rra.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    6(r15),            r13;\n"
		"and.b  #8,           r13;\n"
		"rra.b  r13;\n"
		"rra.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    1(r15),            r13;\n"
		"and.b  #8,           r13;\n" 
		"rra.b  r13;\n"
		"rra.b  r13;\n"
		"rra.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    r12,            3(r14);\n"
		
		
		/*---------------------------------------------------------------*/
		"mov.b    18(r15),            r12;\n" /*  roundKeys[i*8 + 4] = ( (uint8_t)( ((tmpKey[18] & 0x1)<<3) | ((tmpKey[13] & 0x1)<<2) | ((tmpKey[9] & 0x1)<<1) | ((tmpKey[3] & 0x1)) )  ) ; */
		"and.b  #1,           r12;\n" 
		"rla.b  r12;\n"
		"rla.b  r12;\n"
		"rla.b  r12;\n"
		
		"mov.b    13(r15),            r13;\n"
		"and.b  #1,           r13;\n" 
		"rla.b  r13;\n"
		"rla.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    9(r15),            r13;\n"
		"and.b  #1,           r13;\n" 
		"rla.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    3(r15),            r13;\n"
		"and.b  #1,           r13;\n" 
		"bis.b  r13,           r12;\n" 
		
		"mov.b    r12,             4(r14);\n"
		
		
		
		"mov.b    18(r15),            r12;\n"
		"and.b  #2,           r12;\n" 
		"rla.b  r12;\n"
		"rla.b  r12;\n"
		
		"mov.b    13(r15),            r13;\n"
		"and.b  #2,           r13;\n" 
		"rla.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    9(r15),            r13;\n"
		"and.b  #2,           r13;\n" 
		"bis.b  r13,           r12;\n" 
		
		"mov.b    3(r15),            r13;\n"
		"and.b  #2,           r13;\n" 
		"rra.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    r12,             5(r14);\n"
		
		
		
		"mov.b    18(r15),            r12;\n"
		"and.b  #4,           r12;\n" 
		"rla.b  r12;\n"
		
		"mov.b    13(r15),            r13;\n"
		"and.b  #4,           r13;\n" 
		"bis.b  r13,           r12;\n" 
		
		"mov.b    9(r15),            r13;\n"
		"and.b  #4,           r13;\n"
		"rra.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    3(r15),            r13;\n"
		"and.b  #4,           r13;\n" 
		"rra.b  r13;\n"
		"rra.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    r12,             6(r14);\n"
		
		
		
		"mov.b    18(r15),            r12;\n"
		"and.b  #8,           r12;\n" 
				
		"mov.b    13(r15),            r13;\n"
		"and.b  #8,           r13;\n" 
		"rra.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    9(r15),            r13;\n"
		"and.b  #8,           r13;\n"
		"rra.b  r13;\n"
		"rra.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    3(r15),            r13;\n"
		"and.b  #8,           r13;\n" 
		"rra.b  r13;\n"
		"rra.b  r13;\n"
		"rra.b  r13;\n"
		"bis.b  r13,           r12;\n" 
		
		"mov.b    r12,            7(r14);\n"
		
		/*---------------------------------------------------------------*/
        /* SBOX                                            				 */
        /*---------------------------------------------------------------*/
        "mov.b  0(r14),            r6;\n" 
		"mov.b  S(r6),        0(r14);\n"
		
		"mov.b  1(r14),            r6;\n" 
		"mov.b  S(r6),        1(r14);\n"
		
		"mov.b  2(r14),            r6;\n" 
		"mov.b  S(r6),        2(r14);\n"
		
		"mov.b  3(r14),            r6;\n" 
		"mov.b  S(r6),        3(r14);\n"
		
		"mov.b  4(r14),            r6;\n" 
		"mov.b  S(r6),        4(r14);\n"
		
		"mov.b  5(r14),            r6;\n" 
		"mov.b  S(r6),        5(r14);\n"
		
		"mov.b  6(r14),            r6;\n" 
		"mov.b  S(r6),        6(r14);\n"
		
		"mov.b  7(r14),            r6;\n" 
		"mov.b  S(r6),        7(r14);\n"
		
		/*--------------------------------------------------*/
		"mov.b #30,            r6;\n" /* roundKeys[i*8 + 7] ^= ( ((i<<7 & 0x80) ^ (i>>1 & 0x0f) ) & 0x0f ); then roundKeys[i*8 + 6] ^= (( ((i<<7 & 0x80) ^ (i>>1 & 0x0f) ) & 0xf0 ) >>4); */
		"sub.b r11,            r6;\n"
		"mov.b r6,            r12;\n"
		"rra.b  r12;\n"
		"rla.b  r6;\n"
		"rla.b  r6;\n"
		"rla.b  r6;\n"
		"rla.b  r6;\n"
		"rla.b  r6;\n"
		"rla.b  r6;\n"
		"rla.b  r6;\n"
		"and.b  #128,            r6;\n"
		"and.b  #15,            r12;\n"
		"xor.b  r12,        r6;\n"
		"mov.b r6,            r12;\n"
		"and.b  #15,            r6;\n"
		"xor.b  7(r14),        r6;\n"
		"mov.b r6,             7(r14);\n"
		"and.b  #240,            r12;\n"
		"rra.b  r12;\n"
		"rra.b  r12;\n"
		"rra.b  r12;\n"
		"rra.b  r12;\n"
		"and.b  #15,            r12;\n"
		"xor.b  6(r14),        r12;\n"
		"mov.b r12,             6(r14);\n"
		
		/*--------------------------------------------------*/
		"add    #8,            r14;\n" /* key_offset += 8;             */
		
		/*--------------------------------------------------*/
		"dec    r11;                \n" /* while(r11 != 0)  */
        "jz     key_schedule_end;\n"
        
        /*--------------------------------------------------*/
        /* Mixing LFSM +Permutations LFSM     			    */
        /*--------------------------------------------------*/
        "mov.b  0(r15),            r6;\n" /* 1st lfsr - temp = tmpKey[0] ; */
        "mov.b  4(r15),            r13;\n" /* tmpKey[0] = tmpKey[4]; */
		"mov.b  r13,            0(r15);\n" 
		"mov.b  3(r15),            4(r15);\n"/* tmpKey[4] = tmpKey[3]; */
		"mov.b  2(r15),            r12;\n" /*tmpKey[3] = tmpKey[2];*/
		"mov.b  r12,            3(r15);\n"
		"rra.b  r12;\n" /* tmpKey[2] = tmpKey[1] ^ (tmpKey[2]>>3); */
		"rra.b  r12;\n"
		"rra.b  r12;\n"
        "xor.b  1(r15),        r12;\n"
        "mov.b  r12,            2(r15);\n"
        "mov.b  r13,            r12;\n" /* tmpKey[1] = temp ^ (tmpKey[0]>>1) ^ ( (tmpKey[0]<<3) & 0x0f); */
        "rra.b  r12;\n"
        "rla.b  r13;\n"
        "rla.b  r13;\n"
        "rla.b  r13;\n"
        "and.b  #15,            r13;\n"
        "xor.b  r13,            r12;\n"
        "xor.b  r6,            r12;\n"
        "mov.b  r12,            1(r15);\n"
        
        /*--------------------------------------------------*/
        "mov.b  5(r15),            r6;\n"  /* 2nd lfsr */
        "mov.b  8(r15),            r13;\n"
        "mov.b  r13,            r12;\n"
        "mov.b  r13,            r7;\n"
        "rla.b  r13;\n"
        "and.b  #15,            r13;\n"
        "rra.b  r12;\n"
		"rra.b  r12;\n"
		"rra.b  r12;\n"
		"xor.b  r13,            r12;\n"
		"xor.b  9(r15),         r12;\n"
		"mov.b  r12,            5(r15);\n"
		"mov.b  r7,            9(r15);\n"
		"mov.b  7(r15),            r12;\n"
		"mov.b  r12,            8(r15);\n"
		"rla.b  r12;\n"
		"rla.b  r12;\n"
		"rla.b  r12;\n"
		"and.b  #15,            r12;\n"
		"xor.b  6(r15),            r12;\n"
		"mov.b  r12,            7(r15);\n"
		"mov.b  r6,            6(r15);\n"
				
        /*--------------------------------------------------*/
        "mov.b  10(r15),            r6;\n" /* 3rd lfsr */
        "mov.b  14(r15),            10(r15);\n"
        "mov.b  12(r15),            r7;\n" 
        "mov.b  r7,            r12;\n" 
        "rra.b  r7;\n"
		"rra.b  r7;\n"
		"rra.b  r7;\n"
		"xor.b  13(r15),            r7;\n"
        "mov.b  r7,            14(r15);\n"
        "mov.b  r12,            13(r15);\n"
        "mov.b  r12,            r13;\n" 
        "rra.b  r12;\n"
        "rla.b  r13;\n"
		"rla.b  r13;\n"
		"rla.b  r13;\n"
		"and.b  #15,            r13;\n"
		"xor.b  r12,            r13;\n"
		"xor.b  11(r15),            r13;\n"
		"mov.b  r13,            12(r15);\n" 
		"mov.b  r6,            11(r15);\n" 
		
		
		/*--------------------------------------------------*/
        "mov.b  15(r15),            r6;\n"  /* 4th lfsr */
        "mov.b  19(r15),            15(r15);\n"
        "mov.b  18(r15),            19(r15);\n"
        "mov.b  17(r15),            r12;\n"
        "mov.b  r12,            18(r15);\n"
        "mov.b  r12,            r13;\n"
        "rla.b  r13;\n"
        "and.b  #15,            r13;\n"
        "rra.b  r12;\n"
		"rra.b  r12;\n"
		"rra.b  r12;\n"
		"xor.b  r12,            r13;\n"
		"xor.b  16(r15),            r13;\n"
		"mov.b  r6,            r12;\n"
        "rla.b  r12;\n"
        "rla.b  r12;\n"
        "rla.b  r12;\n"
        "and.b  #15,            r12;\n"
        "xor.b  r12,            r13;\n"
        "mov.b  r13,            17(r15);\n"
        "mov.b  r6,            16(r15);\n"
         
        
        
		"jmp    key_schedule_round_loop; \n"
		
		/*--------------------------------------------------*/

"key_schedule_end:                \n"
		
		
		/*---------------------------------------------------------------*/
        /* Restore initial key                                           */
        /*---------------------------------------------------------------*/
        "pop    19(r15);                \n"
        "pop    18(r15);                \n"
        "pop    17(r15);                \n"
        "pop    16(r15);                \n"
		"pop    15(r15);                \n"
        "pop    14(r15);                \n"
        "pop    13(r15);                \n"
        "pop    12(r15);                \n"
        "pop    11(r15);                \n"
		"pop    10(r15);                \n"
        "pop    9(r15);                \n"
        "pop    8(r15);                \n"
        "pop    7(r15);                \n"
        "pop    6(r15);                \n"
		"pop    5(r15);                \n"
        "pop    4(r15);                \n"
        "pop    3(r15);                \n"
        "pop    2(r15);                \n"
        "pop    1(r15);                \n"
		"pop    0(r15);                \n"
		
		
		/*---------------------------------------------------------------*/
        /* Restore registers                                             */
        /*---------------------------------------------------------------*/
        "pop    r15;                \n"
        "pop    r14;                \n"
        "pop    r13;                \n"
        "pop    r12;                \n"
        "pop    r11;                \n"
        "pop    r10;                \n"
        "pop    r9;                 \n"
        "pop    r8;                 \n"
        "pop    r7;                 \n"
        "pop    r6;                 \n"
        "pop    r5;                 \n"
        /*---------------------------------------------------------------*/
    :
    : [key] "m" (key), [roundKeys] "m" (roundKeys), [S] "" (S)); 
}


#else
#ifdef ARM
/*----------------------------------------------------------------------------*/
/* Optimized for ARM                                                          */
/*----------------------------------------------------------------------------*/

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    asm volatile (\
        /*--------------------------------------------------------------------*/
        /* r0  - Block 0-3      /  RK 0-3                                     */
        /* r1  - Block 4-7       /  RK 4-7                                    */
        /* r2  - Block 8-11      /  Temporary                                 */
        /* r3  - Block 12-15     /  Temporary                                 */
        /* r4  - Block  / temporary                                           */
        /* r5  - Block right                                                  */
        /* r6  - Block left                                                   */
        /* r7  - roundkey                                                     */
        /* r8  - Sbox                                                         */
        /* r9  - roundkey                                                     */
        /* r10 - Temporary 1                                                  */
        /* r11 - Temporary 2        / counteur                                */
        /* r12 - Temporary 3      / counteur                                  */
        /* lr  - 255 for masking                                              */
        /*--------------------------------------------------------------------*/
        /* Store all modified registers                                       */
        /*--------------------------------------------------------------------*/
        "stmdb        sp!,   {r0-r12,lr};              \n" 
        /*--------------------------------------------------------------------*/
        "mov           r0,        %[key];              \n" 
        "mov           r1,  %[roundKeys];              \n" 
        "ldr           r6,         =S;              \n"
        
        
        /*--------------------------------------------------------------------*/
        "ldmia         r0,      {r8-r12};              \n" 
        
        "mov           r7,           #30;              \n"
"key_schedule_round_loop:    \n"
        
        /*--------------------------------------------------------------------*/
        /* Extract Round Key                                                 */
        /*--------------------------------------------------------------------*/
         
        
        "and	 	   r2, 		r12, 	0x00000001;              \n" 
        "lsl	 	   r2, 		r2, 	#3;              \n" 
        "and	 	   r3, 		r10, 	0x00010000;              \n" 
        "lsr	 	   r3, 		r3, 	#14;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "and	 	   r3, 		r9, 	0x00010000;              \n" 
        "lsr	 	   r3, 		r3, 	#15;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "and	 	   r3, 		r8, 	0x00000100;              \n" 
        "lsr	 	   r3, 		r3, 	#8;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "ldrb          r2,      [r6, r2];              \n" /* r2=sbox(r2)     */
        
        "mov           r4,        r2;              \n" 
        
        
        "and	 	   r2, 		r12, 	0x00000002;              \n" 
        "lsl	 	   r2, 		r2, 	#2;              \n" 
        "and	 	   r3, 		r10, 	0x00020000;              \n" 
        "lsr	 	   r3, 		r3, 	#15;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "and	 	   r3, 		r9, 	0x00020000;              \n" 
        "lsr	 	   r3, 		r3, 	#16;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "and	 	   r3, 		r8, 	0x00000200;              \n" 
        "lsr	 	   r3, 		r3, 	#9;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "ldrb          r2,      [r6, r2];              \n" /* r2=sbox(r2)     */
        "lsl	 	   r2, 		r2, 	#8;              \n"
        
        "orr	 	   r4, 		r4, 	r2;              \n" 
        
        
        "and	 	   r2, 		r12, 	0x00000004;              \n" 
        "lsl	 	   r2, 		r2, 	#1;              \n" 
        "and	 	   r3, 		r10, 	0x00040000;              \n" 
        "lsr	 	   r3, 		r3, 	#16;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "and	 	   r3, 		r9, 	0x00040000;              \n" 
        "lsr	 	   r3, 		r3, 	#17;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "and	 	   r3, 		r8, 	0x00000400;              \n" 
        "lsr	 	   r3, 		r3, 	#10;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "ldrb          r2,      [r6, r2];              \n" /* r2=sbox(r2)     */
        "lsl	 	   r2, 		r2, 	#16;              \n"
        
        "orr	 	   r4, 		r4, 	r2;              \n"
        
        
        "and	 	   r2, 		r12, 	0x00000008;              \n" 
        "and	 	   r3, 		r10, 	0x00080000;              \n" 
        "lsr	 	   r3, 		r3, 	#17;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "and	 	   r3, 		r9, 	0x00080000;              \n" 
        "lsr	 	   r3, 		r3, 	#18;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "and	 	   r3, 		r8, 	0x00000800;              \n" 
        "lsr	 	   r3, 		r3, 	#11;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "ldrb          r2,      [r6, r2];              \n" /* r2=sbox(r2)     */
        "lsl	 	   r2, 		r2, 	#24;              \n"
        
        "orr	 	   r4, 		r4, 	r2;              \n"
        
        
        
        
        
        
        "and	 	   r2, 		r12, 	0x00010000;              \n" 
        "lsr	 	   r2, 		r2, 	#13;              \n" 
        "and	 	   r3, 		r11, 	0x00000100;              \n" 
        "lsr	 	   r3, 		r3, 	#6;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "and	 	   r3, 		r10, 	0x00000100;              \n" 
        "lsr	 	   r3, 		r3, 	#7;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "and	 	   r3, 		r8, 	0x01000000;              \n" 
        "lsr	 	   r3, 		r3, 	#24;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "ldrb          r2,      [r6, r2];              \n" /* r2=sbox(r2)     */
        
        "mov           r5,        r2;              \n" 
        
        
        "and	 	   r2, 		r12, 	0x00020000;              \n" 
        "lsr	 	   r2, 		r2, 	#14;              \n" 
        "and	 	   r3, 		r11, 	0x00000200;              \n" 
        "lsr	 	   r3, 		r3, 	#7;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "and	 	   r3, 		r10, 	0x00000200;              \n" 
        "lsr	 	   r3, 		r3, 	#8;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "and	 	   r3, 		r8, 	0x02000000;              \n" 
        "lsr	 	   r3, 		r3, 	#25;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "ldrb          r2,      [r6, r2];              \n" /* r2=sbox(r2)     */
        "lsl	 	   r2, 		r2, 	#8;              \n"
        
        "orr	 	   r5, 		r5, 	r2;              \n" 
        
        
        "and	 	   r2, 		r12, 	0x00040000;              \n" 
        "lsr	 	   r2, 		r2, 	#15;              \n" 
        "and	 	   r3, 		r11, 	0x00000400;              \n" 
        "lsr	 	   r3, 		r3, 	#8;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "and	 	   r3, 		r10, 	0x00000400;              \n" 
        "lsr	 	   r3, 		r3, 	#9;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "and	 	   r3, 		r8, 	0x04000000;              \n" 
        "lsr	 	   r3, 		r3, 	#26;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "ldrb          r2,      [r6, r2];              \n" /* r2=sbox(r2)     */
        
        "mov	 	   r0, 		#30;              \n"
        "sub	 	   r0, 		r0, 	r7;              \n"
        "mov	 	   r3, 		r0;              \n"
        "lsr	 	   r0, 		r0, 	#1;              \n"
        "lsl	 	   r3, 		r3, 	#7;              \n"
        "and	 	   r3, 		r3, 	0x80;              \n"
        "and	 	   r0, 		r0, 	0x0f;              \n"
        "eor	 	   r0, 		r0, 	r3;              \n"
        "and	 	   r3, 		r0, 	0xf0;              \n"
        "lsr	 	   r3, 		r3, 	#4;              \n"
        "eor	 	   r2, 		r2, 	r3;              \n"
        
        "lsl	 	   r2, 		r2, 	#16;              \n"
        
        "orr	 	   r5, 		r5, 	r2;              \n"
        
        
        "and	 	   r2, 		r12, 	0x00080000;              \n" 
        "lsr	 	   r2, 		r2, 	#16;              \n" 
        "and	 	   r3, 		r11, 	0x00000800;              \n" 
        "lsr	 	   r3, 		r3, 	#9;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "and	 	   r3, 		r10, 	0x00000800;              \n" 
        "lsr	 	   r3, 		r3, 	#10;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "and	 	   r3, 		r8, 	0x08000000;              \n" 
        "lsr	 	   r3, 		r3, 	#27;              \n" 
        "orr	 	   r2, 		r2, 	r3;              \n" 
        "ldrb          r2,      [r6, r2];              \n" /* r2=sbox(r2)     */
        
        "and	 	   r0, 		r0, 	0x0f;              \n"
        "eor	 	   r2, 		r2, 	r0;              \n"
        
        "lsl	 	   r2, 		r2, 	#24;              \n"
        
        "orr	 	   r5, 		r5, 	r2;              \n"
        
        
        
        "stmia         r1!,     {r4-r5};              \n"
        
        /*--------------------------------------------------------------------*/
        "subs          r7,            r7,           #1;\n"
        "beq           key_schedule_last_round;         \n" 
        
        /*--------------------------------------------------------------------*/
        /* Permutation                                                        */
        /*--------------------------------------------------------------------*/
         "and	 	   r0, 		r8, 	0x0f000000;              \n"
         "lsr	 	   r0, 		r0, 	#24;              \n"
         "lsl	 	   r8, 		r8, 	#8;              \n"
         
         "and	 	   r2, 		r9, 	0x0000000f;              \n"
         "orr	 	   r8, 		r8, 	r2;              \n"
         
         "ldr r3, =(0x0f0f0f00)\n"
         "and	 	   r9, 		r9, 	r3;              \n"
         "and	 	   r2, 		r9, 	0x0f000000;              \n"
         "lsr	 	   r2, 		r2, 	#24;              \n"
         "lsl	 	   r9, 		r9, 	#8;              \n"
         "orr	 	   r9, 		r9, 	r0;              \n"
         "and	 	   r0, 		r10, 	0x00000f00;              \n"
         "orr	 	   r9, 		r9, 	r0;              \n"
         
         "and	 	   r0, 		r10, 	0x0f000000;              \n"
         "lsr	 	   r0, 		r0, 	#24;              \n"
         "lsl	 	   r10, 		r10, 	#8;              \n"
         "orr	 	   r10, 		r10, 	r2;              \n"
         "ldr r3, =(0x0f000f0f)\n"
         "and	 	   r10, 		r10, 	r3;              \n"
         "and	 	   r2, 		r11, 	0x000f0000;              \n"
         "orr	 	   r10, 		r10, 	r2;              \n"
         
         "and	 	   r2, 		r11, 	0x0f000000;              \n"
         "lsr	 	   r2, 		r2, 	#24;              \n"
         "lsl	 	   r11, 		r11, 	#8;              \n"
         "orr	 	   r11, 		r11, 	r0;              \n"
         "ldr r3, =(0x000f0f0f)\n"
         "and	 	   r11, 		r11, 	r3;              \n"
         "and	 	   r0, 		r12, 	0x0f000000;              \n"
         "orr	 	   r11, 		r11, 	r0;              \n"
         
         "lsl	 	   r12, 		r12, 	#8;              \n"
         "orr	 	   r12, 		r12, 	r2;              \n"
         
         
        /*--------------------------------------------------------------------*/
        /* Mixing LFSM 				                                          */
        /*--------------------------------------------------------------------*/
        "lsr	 	   r2, 		r8, 	#11;              \n"
        "and	 	   r2, 		r2, 	0x000f0000;              \n"
        "eor	 	   r8, 		r8, 	r2;              \n"
        "lsl	 	   r2, 		r8, 	#7;              \n"
        "lsl	 	   r0, 		r8, 	#11;              \n"
        "eor	 	   r2, 		r2, 	r0;              \n"
        "and	 	   r2, 		r2, 	0x00000f00;              \n"
        "eor	 	   r8, 		r8, 	r2;              \n"
        
        "lsl	 	   r2, 		r10, 	#1;              \n"
        "lsr	 	   r0, 		r10, 	#3;              \n"
        "eor	 	   r2, 		r2, 	r0;              \n"
        "and	 	   r2, 		r2, 	0x00000f00;              \n"       
        "eor	 	   r9, 		r9, 	r2;              \n"
        "lsl	 	   r2, 		r10, 	#27;              \n"
        "and	 	   r2, 		r2, 	0x0f000000;              \n"
        "eor	 	   r9, 		r9, 	r2;              \n"
        
        "lsl	 	   r2, 		r11, 	#5;              \n"
        "and	 	   r2, 		r2, 	0x000f0000;              \n"
        "eor	 	   r11, 		r11, 	r2;              \n"
        "lsr	 	   r2, 		r11, 	#9;              \n"
        "lsr	 	   r0, 		r11, 	#5;              \n"
        "eor	 	   r2, 		r2, 	r0;              \n"
        "and	 	   r2, 		r2, 	0x0000000f;              \n"
        "eor	 	   r11, 		r11, 	r2;              \n"
        
        "lsr	 	   r2, 		r12, 	#7;              \n"
        "lsr	 	   r0, 		r12, 	#11;              \n"
        "eor	 	   r2, 		r2, 	r0;              \n"
        "lsl	 	   r0, 		r12, 	#11;              \n"
        "eor	 	   r2, 		r2, 	r0;              \n"
        "and	 	   r2, 		r2, 	0x00000f00;              \n"
        "eor	 	   r12, 		r12, 	r2;              \n"
        
        /*--------------------------------------------------------------------*/
        "b             key_schedule_round_loop;             \n"
        /*--------------------------------------------------------------------*/
"key_schedule_last_round:                               \n"
        
        /*--------------------------------------------------------------------*/
        /* Restore registers                                                  */
        /*--------------------------------------------------------------------*/
        "ldmia        sp!,      {r0-r12,lr};           \n" /*                 */
        /*--------------------------------------------------------------------*/
    :
    : [key] "r" (key), [roundKeys] "r" (roundKeys)  
); 
}

#else
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	int8_t i;
  	
  	uint8_t tmpKey[20];
  memcpy(tmpKey, key, 20);

  /* 29 rounds */
  for(i = 0 ; i < 29 ; i++)
  {
    /* ExtractRoundKey */ 
		
		roundKeys[i*8 + 7] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[18] & 0x8)) | ((tmpKey[13] & 0x8)>>1) | ((tmpKey[9] & 0x8)>>2) | ((tmpKey[3] & 0x8)>>3) ) ) ]) ; 
		roundKeys[i*8 + 6] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[18] & 0x4)<<1) | ((tmpKey[13] & 0x4)) | ((tmpKey[9] & 0x4)>>1) | ((tmpKey[3] & 0x4)>>2) ) )]);
		
		roundKeys[i*8 + 5] = READ_SBOX_BYTE(S[((uint8_t)( ((tmpKey[18] & 0x2)<<2) | ((tmpKey[13] & 0x2)<<1) | ((tmpKey[9] & 0x2)) | ((tmpKey[3] & 0x2)>>1) ) ) ]); 
		roundKeys[i*8 + 4] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[18] & 0x1)<<3) | ((tmpKey[13] & 0x1)<<2) | ((tmpKey[9] & 0x1)<<1) | ((tmpKey[3] & 0x1)) )  ) ]);
		
		roundKeys[i*8 + 3] = READ_SBOX_BYTE(S[ ((uint8_t)( ((tmpKey[16] & 0x8)) | ((tmpKey[10] & 0x8)>>1) | ((tmpKey[6] & 0x8)>>2) | ((tmpKey[1] & 0x8)>>3) ) ) ]); 
		roundKeys[i*8 + 2] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[16] & 0x4)<<1) | ((tmpKey[10] & 0x4)) | ((tmpKey[6] & 0x4)>>1) | ((tmpKey[1] & 0x4)>>2)  ) ) ]);
		
		roundKeys[i*8 + 1] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[16] & 0x2)<<2) | ((tmpKey[10] & 0x2)<<1) | ((tmpKey[6] & 0x2)) | ((tmpKey[1] & 0x2)>>1) ) ) ]) ; 
		roundKeys[i*8 + 0] =  READ_SBOX_BYTE(S[((uint8_t)( ((tmpKey[16] & 0x1)<<3) | ((tmpKey[10] & 0x1)<<2) | ((tmpKey[6] & 0x1)<<1) | ((tmpKey[1] & 0x1)) ) )]);
		
    	roundKeys[i*8 + 7] ^= ( ((i<<7 & 0x80) ^ (i>>1 & 0x0f) ) & 0x0f );
    	roundKeys[i*8 + 6] ^= (( ((i<<7 & 0x80) ^ (i>>1 & 0x0f) ) & 0xf0 ) >>4);
    
    /* MixingLFSM + PermutationLFSM */
		uint8_t temp;
		/* 1er lfsr */
		temp = tmpKey[0] ;
		tmpKey[0] = tmpKey[4];
		tmpKey[4] = tmpKey[3];
		tmpKey[3] = tmpKey[2];
		tmpKey[2] = tmpKey[1] ^ (tmpKey[2]>>3);
    	tmpKey[1] = temp ^ (tmpKey[0]>>1) ^ ( (tmpKey[0]<<3) & 0x0f);
		
    
    /* 2e lfsr */
		temp = tmpKey[5];
		tmpKey[5] = tmpKey[9] ^ ( (tmpKey[8]<<1) & 0x0f) ^ (tmpKey[8]>>3);
		tmpKey[9] = tmpKey[8];
		tmpKey[8] = tmpKey[7];
		tmpKey[7] = ( (tmpKey[7]<<3) & 0x0f) ^ tmpKey[6];
		tmpKey[6] = temp;
    
    /* 3e lfsr */
		temp = tmpKey[10];
		tmpKey[10] = tmpKey[14];
		tmpKey[14] = tmpKey[13] ^ (tmpKey[12]>>3);
		tmpKey[13] = tmpKey[12];
		tmpKey[12] = (tmpKey[12]>>1) ^ ((tmpKey[12]<<3) & 0x0f) ^ tmpKey[11];
		tmpKey[11] = temp;
    
    /* 4e lfsr */
    	temp = tmpKey[15];
		tmpKey[15] = tmpKey[19];
		tmpKey[19] = tmpKey[18];
		tmpKey[18] = tmpKey[17];
		tmpKey[17] = ( ((tmpKey[17]<<1) & 0x0f) ^ (tmpKey[17]>>3) ) ^ (tmpKey[16] ^ ( (temp<<3) & 0x0f));
		tmpKey[16] = temp;
        
  }
  
  /* last ExtractRoundKey */

  /* ExtractRoundKey	 */
	roundKeys[i*8 + 7] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[18] & 0x8)) | ((tmpKey[13] & 0x8)>>1) | ((tmpKey[9] & 0x8)>>2) | ((tmpKey[3] & 0x8)>>3) ) ) ]) ; 
	roundKeys[i*8 + 6] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[18] & 0x4)<<1) | ((tmpKey[13] & 0x4)) | ((tmpKey[9] & 0x4)>>1) | ((tmpKey[3] & 0x4)>>2) ) )]);
	
	roundKeys[i*8 + 5] = READ_SBOX_BYTE(S[((uint8_t)( ((tmpKey[18] & 0x2)<<2) | ((tmpKey[13] & 0x2)<<1) | ((tmpKey[9] & 0x2)) | ((tmpKey[3] & 0x2)>>1) ) ) ]); 
	roundKeys[i*8 + 4] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[18] & 0x1)<<3) | ((tmpKey[13] & 0x1)<<2) | ((tmpKey[9] & 0x1)<<1) | ((tmpKey[3] & 0x1)) )  ) ]);
	
	roundKeys[i*8 + 3] = READ_SBOX_BYTE(S[ ((uint8_t)( ((tmpKey[16] & 0x8)) | ((tmpKey[10] & 0x8)>>1) | ((tmpKey[6] & 0x8)>>2) | ((tmpKey[1] & 0x8)>>3) ) ) ]); 
	roundKeys[i*8 + 2] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[16] & 0x4)<<1) | ((tmpKey[10] & 0x4)) | ((tmpKey[6] & 0x4)>>1) | ((tmpKey[1] & 0x4)>>2)  ) ) ]);
	
	roundKeys[i*8 + 1] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[16] & 0x2)<<2) | ((tmpKey[10] & 0x2)<<1) | ((tmpKey[6] & 0x2)) | ((tmpKey[1] & 0x2)>>1) ) ) ]) ; 
	roundKeys[i*8 + 0] =  READ_SBOX_BYTE(S[((uint8_t)( ((tmpKey[16] & 0x1)<<3) | ((tmpKey[10] & 0x1)<<2) | ((tmpKey[6] & 0x1)<<1) | ((tmpKey[1] & 0x1)) ) )]);
	
	roundKeys[i*8 + 7] ^= ( ((i<<7 & 0x80) ^ (i>>1 & 0x0f) ) & 0x0f );
	roundKeys[i*8 + 6] ^= (( ((i<<7 & 0x80) ^ (i>>1 & 0x0f) ) & 0xf0 ) >>4);
}
#endif
#endif
#endif


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
/*----------------------------------------------------------------------------*/
/* Optimized for AVR                                                          */
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    asm volatile (\
        /*--------------------------------------------------*/
        /* Registers allocation:                            */
        /*     r0-r15  : state                              */
        /*     r16     : loop counter                       */
        /*     r17     : temporary 0 / RK                   */
        /*     r18     : temporary 1 / RK                   */
        /*     r19     : temporary 2 / RK                   */
        /*     r20     : temporary 3 / RK                   */
        /*     r21     : temporary 4 / RK                   */
        /*     r22     : temporary 5 / RK                   */
        /*     r23     : temporary 6 / RK                   */
        /*     r24     : temporary 7 / RK                   */
        /*     r30:r31 : Z Key / Sbox                       */
        /*--------------------------------------------------*/
        /* Store all modified registers */
        /*--------------------------------------------------*/
        "push  r0;\n"
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
        /*--------------------------------------------------*/
         
        "ldi  r16,    30;\n" /* 30 rounds */
"encrypt_round:          \n"
        /*--------------------------------------------------*/
        /*	Load RK + non linear layer						*/
        /*--------------------------------------------------*/
		"ld   r17,    z+;\n"
		"eor   r17,    r7;\n"
		
		"ld   r18,    z+;\n"
		"eor   r18,    r6;\n"
		
		"ld   r19,    z+;\n"
		"eor   r19,    r5;\n"
		
		"ld   r20,    z+;\n"
		"eor   r20,    r4;\n"
		
		"ld   r21,    z+;\n"
		"eor   r21,    r3;\n"
		
		"ld   r22,    z+;\n"
		"eor   r22,    r2;\n"
		
		"ld   r23,    z+;\n"
		"eor   r23,    r1;\n"
		
		"ld   r24,    z+;\n"
		"eor   r24,    r0;\n"
		
        /*--------------------------------------------------*/
        /* SBOX 											*/
        /*--------------------------------------------------*/
        "push r30;       \n" /* push z                      */ 
        "push r31;       \n"
        "ldi  r30,   lo8(S);\n" /* Load Sbox*/
        "ldi  r31,   hi8(S);\n"
        
        "mov  r30,    r17;\n" 
        "ldi r31, 0;\n"
        "subi r30, lo8(-(S))  ;\n" /* Load Sbox(r17)*/
        "sbci r31, hi8(-(S))  ;\n"
        "lpm r17, Z;\n" /* store sbox(r17) */
        
        "mov  r30,    r18;\n"
        "ldi r31, 0;\n"
        "subi r30, lo8(-(S))  ;\n"
        "sbci r31, hi8(-(S))  ;\n"
        "lpm r18, Z;\n"
        
        "mov  r30,    r19;\n"
        "ldi r31, 0;\n"
        "subi r30, lo8(-(S))  ;\n"
        "sbci r31, hi8(-(S))  ;\n"
        "lpm r19, Z;\n"
        
        "mov  r30,    r20;\n"
        "ldi r31, 0;\n"
        "subi r30, lo8(-(S))  ;\n"
        "sbci r31, hi8(-(S))  ;\n"
        "lpm r20, Z;\n"
        
        "mov  r30,    r21;\n"
        "ldi r31, 0;\n"
        "subi r30, lo8(-(S))  ;\n"
        "sbci r31, hi8(-(S))  ;\n"
        "lpm r21, Z;\n"
        
        "mov  r30,    r22;\n"
        "ldi r31, 0;\n"
        "subi r30, lo8(-(S))  ;\n"
        "sbci r31, hi8(-(S))  ;\n"
        "lpm r22, Z;\n"
        
        "mov  r30,    r23;\n"
        "ldi r31, 0;\n"
        "subi r30, lo8(-(S))  ;\n"
        "sbci r31, hi8(-(S))  ;\n"
        "lpm r23, Z;\n"
        
        "mov  r30,    r24;\n"
        "ldi r31, 0;\n"
        "subi r30, lo8(-(S))  ;\n"
        "sbci r31, hi8(-(S))  ;\n"
        "lpm r24, Z;\n"
        
        "pop  r31;       \n"
        "pop  r30;       \n"
                                           
        /*--------------------------------------------------*/
        /*	Linear Layer									*/
        /*--------------------------------------------------*/
        "eor   r8,    r17;\n"
        
        "eor   r18,    r7;\n"
        "eor   r9,    r18;\n"
        
        "eor   r19,    r7;\n"
        "eor   r10,    r19;\n"
        
        "eor   r20,    r7;\n"
        "eor   r11,    r20;\n"
        
        "eor   r21,    r7;\n"
        "eor   r12,    r21;\n"
        
        "eor   r22,    r7;\n"
        "eor   r13,    r22;\n"
        
        "eor   r23,    r7;\n"
        "eor   r14,    r23;\n"
        
        "eor   r24,    r7;\n"
        "eor   r24,    r6;\n"
        "eor   r24,    r5;\n"
        "eor   r24,    r4;\n"
        "eor   r24,    r3;\n"
        "eor   r24,    r2;\n"
        "eor   r24,    r1;\n"
        "eor   r15,    r24;\n"
        /*--------------------------------------------------*/
        "dec  r16;       \n"
        
        "brne encrypt_permutation;\n"
        "jmp  encrypt_final_round;\n"
        
        
        /*--------------------------------------------------*/
        /* PERMUTATIONS 									*/
        /*--------------------------------------------------*/
"encrypt_permutation:\n"        
        "mov   r17,    r1;\n"
        "mov   r1,    r11;\n"
        "mov   r11,    r5;\n"
        "mov   r5,    r9;\n"
        "mov   r9,    r17;\n"
        
        "mov   r17,    r2;\n"
        "mov   r2,    r12;\n"
        "mov   r12,    r6;\n"
        "mov   r6,    r13;\n"
        "mov   r13,    r0;\n"
        "mov   r0,    r14;\n"
        "mov   r14,    r17;\n"
        
        "mov   r17,    r3;\n"
        "mov   r3,    r10;\n"
        "mov   r10,    r4;\n"
        "mov   r4,    r8;\n"
        "mov   r8,    r17;\n"
        
        "mov   r17,    r7;\n"
        "mov   r7,    r15;\n"
        "mov   r15,    r17;\n"
        
        
        "jmp encrypt_round;\n"


		/*--------------------------------------------------*/
"encrypt_final_round:\n"



        /*--------------------------------------------------*/
        /* Store back the state                             */
        /*--------------------------------------------------*/
        "st    -x,   r15;\n"
        "st    -x,   r14;\n"
        "st    -x,   r13;\n"
        "st    -x,   r12;\n"
        "st    -x,   r11;\n"
        "st    -x,   r10;\n"
        "st    -x,    r9;\n"
        "st    -x,    r8;\n"
        "st    -x,    r7;\n"
        "st    -x,    r6;\n"
        "st    -x,    r5;\n"
        "st    -x,    r4;\n"
        "st    -x,    r3;\n"
        "st    -x,    r2;\n"
        "st    -x,    r1;\n"
        "st    -x,    r0;\n"
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
        "clr   r1;\n" 
        "pop   r0;\n"
        /*--------------------------------------------------*/
    :
    : [block] "x" (block), [roundKeys] "z" (roundKeys), [S] "" (S)
); 
}



#else

/*----------------------------------------------------------------------------*/
/* Optimized for MSP                                                          */
/*----------------------------------------------------------------------------*/
#ifdef MSP
/*----------------------------------------------------------------------------*/
/* Assembly                                                                   */
/*----------------------------------------------------------------------------*/
void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    asm volatile (\
        /*--------------------------------------------------*/
        /* r6  - Temporary 1                                */
        /* r7  - Temporary 2                                */
        /* r13 - Loop counter                               */
        /* r14 - RoundKeys                                  */
        /* r15 - Block                                      */
        /*--------------------------------------------------*/
        /* Store all modified registers                     */
        /*--------------------------------------------------*/
        
        "push   r6;                 \n"
        "push   r7;                 \n"
        "push   r13;                \n"
        "push   r14;                \n"
        "push   r15;                \n"
        
        /*--------------------------------------------------*/
        "mov    %[block],       r15;\n"
        "mov    %[roundKeys],   r14;\n"
        
        /*--------------------------------------------------*/
        "mov    #30,            r13;\n" /* 30 rounds */
"encrypt_round_loop:                \n"


        /*--------------------------------------------------*/
		"mov.b  7(r15),            r6;\n" /* @block[7]        */     
        "xor.b  @r14+,           r6;\n" /* r6^=@rk[0]++        */
		"xor.b  S(r6),           8(r15);\n" /* @block[8]=sbox(r6)       */
		
		
		"mov.b  7(r15),            r7;\n" /* @block[7]        */
		
		"mov.b  6(r15),            r6;\n" /* @block[6]        */     
        "xor.b  @r14+,           r6;\n" /* r6^=@rk[1]++        */
        "mov.b  S(r6),        r6;\n" /* r6=sbox(r6) */
        "xor.b  r7,           r6;\n" /* r6^=r7        */
		"xor.b  r6,           9(r15);\n" /* @block[6]^=r6        */
		
		
		"mov.b  5(r15),            r6;\n"    
        "xor.b  @r14+,           r6;\n" 
        "mov.b  S(r6),        r6;\n" 
        "xor.b  r7,           r6;\n" 
		"xor.b  r6,           10(r15);\n" 
		
		
		"mov.b  4(r15),            r6;\n"    
        "xor.b  @r14+,           r6;\n" 
        "mov.b  S(r6),        r6;\n" 
        "xor.b  r7,           r6;\n" 
		"xor.b  r6,           11(r15);\n" 
		
		
		"mov.b  3(r15),            r6;\n"     
        "xor.b  @r14+,           r6;\n" 
        "mov.b  S(r6),        r6;\n" 
        "xor.b  r7,           r6;\n" 
		"xor.b  r6,           12(r15);\n" 
		
		
		"mov.b  2(r15),            r6;\n"     
        "xor.b  @r14+,           r6;\n" 
        "mov.b  S(r6),        r6;\n"
        "xor.b  r7,           r6;\n" 
		"xor.b  r6,           13(r15);\n" 
		
		
		"mov.b  1(r15),            r6;\n"     
        "xor.b  @r14+,           r6;\n" 
        "mov.b  S(r6),        r6;\n" 
        "xor.b  r7,           r6;\n" 
		"xor.b  r6,           14(r15);\n" 
		
		
		"mov.b  0(r15),            r6;\n"    
        "xor.b  @r14+,           r6;\n" 
        "mov.b  S(r6),        r6;\n" 
        "xor.b  r7,           r6;\n"
        "xor.b  1(r15),           r6;\n" 
        "xor.b  2(r15),           r6;\n" 
        "xor.b  3(r15),           r6;\n" 
        "xor.b  4(r15),           r6;\n" 
        "xor.b  5(r15),           r6;\n" 
        "xor.b  6(r15),           r6;\n" 
		"xor.b  r6,           15(r15);\n" 

        /*--------------------------------------------------*/
		"dec    r13;                \n" /* while(r13 != 0)  */
        "jz     encrypt_end;\n"
        
        /*--------------------------------------------------*/
        /* Permutations      							    */
        /*--------------------------------------------------*/
        "mov.b  1(r15),            r6;\n" 
        "mov.b  11(r15),            1(r15);\n" 
        "mov.b  5(r15),            11(r15);\n" 
		"mov.b  9(r15),            5(r15);\n" 
		"mov.b  r6,            9(r15);\n" 
		
		"mov.b  2(r15),            r6;\n" 
        "mov.b  12(r15),            2(r15);\n" 
        "mov.b  6(r15),            12(r15);\n" 
		"mov.b  13(r15),            6(r15);\n" 
		"mov.b  0(r15),            13(r15);\n" 
		"mov.b  14(r15),            0(r15);\n" 
		"mov.b  r6,            14(r15);\n" 
		
		"mov.b  3(r15),            r6;\n" 
        "mov.b  10(r15),            3(r15);\n" 
        "mov.b  4(r15),            10(r15);\n" 
		"mov.b  8(r15),            4(r15);\n" 
		"mov.b  r6,            8(r15);\n" 
		
		"mov.b  7(r15),            r6;\n" 
        "mov.b  15(r15),            7(r15);\n" 
        "mov.b  r6,            15(r15);\n" 
        
		
		"jmp    encrypt_round_loop; \n"
        /*--------------------------------------------------*/

"encrypt_end:                \n"
        /*--------------------------------------------------*/
        /* Restore registers                                */
        /*--------------------------------------------------*/
        "pop    r15;                \n"
        "pop    r14;                \n"
        "pop    r13;                \n"
        "pop    r7;                 \n"
        "pop    r6;                 \n"
        /*--------------------------------------------------*/
    :
    : [block] "m" (block), [roundKeys] "m" (roundKeys), [S] "" (S)
); 
}



#else
#ifdef ARM
/*----------------------------------------------------------------------------*/
/* Optimized for ARM                                                          */
/*----------------------------------------------------------------------------*/

void Encrypt(uint8_t *block, uint8_t *roundKeys)
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
        "mov           r4,      %[block];              \n" 
        "mov           r9,  %[roundKeys];              \n" 
        "ldr           r8,         =S;              \n" /* SBOX */
        /*--------------------------------------------------------------------*/
        /* Load MESSAGE                                                         */
        /*--------------------------------------------------------------------*/
        "ldmia 		  r4,       {r0-r3};              \n"
        "stmdb        sp!,          {r4};              \n"
        
        "and 		  r6,       r3, 	0x0f000000;              \n" 
        "lsl 		  r6,       r6, 	#4;              \n"
        "and 		  r4,       r3, 	0x000f0000;              \n"
        "lsl 		  r4,       r4, 	#8;              \n"
        "orr 		  r6,       r6, 	r4;              \n"
        "and 		  r4,       r3, 	0x00000f00;              \n"
        "lsl 		  r4,       r4, 	#12;              \n"
        "orr 		  r6,       r6, 	r4;              \n"
        "and 		  r4,       r3, 	0x0000000f;              \n"
        "lsl 		  r4,       r4, 	#16;              \n"
        "orr 		  r6,       r6, 	r4;              \n"
        
        "and 		  r4,       r2, 	0x0f000000;              \n" 
        "lsr 		  r4,       r4, 	#12;              \n"
        "orr 		  r6,       r6, 	r4;              \n"
        "and 		  r4,       r2, 	0x000f0000;              \n"
        "lsr 		  r4,       r4, 	#8;              \n"
        "orr 		  r6,       r6, 	r4;              \n"
        "and 		  r4,       r2, 	0x00000f00;              \n"
        "lsr 		  r4,       r4, 	#4;              \n"
        "orr 		  r6,       r6, 	r4;              \n"
        "and 		  r4,       r2, 	0x0000000f;              \n"
        "orr 		  r6,       r6, 	r4;              \n"
        
        "and 		  r5,       r1, 	0x0f000000;              \n" 
        "lsl 		  r5,       r5, 	#4;              \n"
        "and 		  r4,       r1, 	0x000f0000;              \n"
        "lsl 		  r4,       r4, 	#8;              \n"
        "orr 		  r5,       r5, 	r4;              \n"
        "and 		  r4,       r1, 	0x00000f00;              \n"
        "lsl 		  r4,       r4, 	#12;              \n"
        "orr 		  r5,       r5, 	r4;              \n"
        "and 		  r4,       r1, 	0x0000000f;              \n"
        "lsl 		  r4,       r4, 	#16;              \n"
        "orr 		  r5,       r5, 	r4;              \n"
        
        "and 		  r4,       r0, 	0x0f000000;              \n" 
        "lsr 		  r4,       r4, 	#12;              \n"
        "orr 		  r5,       r5, 	r4;              \n"
        "and 		  r4,       r0, 	0x000f0000;              \n"
        "lsr 		  r4,       r4, 	#8;              \n"
        "orr 		  r5,       r5, 	r4;              \n"
        "and 		  r4,       r0, 	0x00000f00;              \n"
        "lsr 		  r4,       r4, 	#4;              \n"
        "orr 		  r5,       r5, 	r4;              \n"
        "and 		  r4,       r0, 	0x0000000f;              \n"
        "orr 		  r5,       r5, 	r4;              \n"
        
        
        /*--------------------------------------------------------------------*/
        "mov           r11,           #30;              \n" /* 30 rounds */
"encrypt_round_loop:  \n"

		/*--------------------------------------------------------------------*/
		/* LOAD RK */
        "ldmia        r9!,      {r0-r1};              \n" /* RK++              */
        "and 		  r7,       r0, 	0x0f000000;              \n" 
        "lsr 		  r7,       r7, 	#8;              \n"
        "and 		  r4,       r0, 	0x000f0000;              \n"
        "lsl 		  r4,       r4, 	#4;              \n"
        "orr 		  r7,       r7, 	r4;              \n"
        "and 		  r4,       r0, 	0x00000f00;              \n"
        "lsl 		  r4,       r4, 	#16;              \n"
        "orr 		  r7,       r7, 	r4;              \n"
        "and 		  r4,       r0, 	0x0000000f;              \n"
        "ror 		  r4,       r4, 	#4;              \n"
        "orr 		  r7,       r7, 	r4;              \n"
        
        "and 		  r4,       r1, 	0x0f000000;              \n" 
        "lsr 		  r4,       r4, 	#24;              \n"
        "orr 		  r7,       r7, 	r4;              \n"
        "and 		  r4,       r1, 	0x000f0000;              \n"
        "lsr 		  r4,       r4, 	#12;              \n"
        "orr 		  r7,       r7, 	r4;              \n"
        "and 		  r4,       r1, 	0x00000f00;              \n"
        "orr 		  r7,       r7, 	r4;              \n"
        "and 		  r4,       r1, 	0x0000000f;              \n"
        "lsl 		  r4,       r4, 	#12;              \n"
        "orr 		  r7,       r7, 	r4;              \n"
        
        
        /*--------------------------------------------------------------------*/
        "mov           lr,          #255;              \n"
        
        "mov           r12,           #0;              \n"
        
"NLL:                                   \n" 
        /*--------------------------------------------------------------------*/
		"AND 			R4, 	r7, 	0xf0000000;              \n" /*Round Key 0*/
		"LSR 			R4, 	r4, 	#28;              \n"
		"AND 			R3, 	r5, 	0xf0000000;              \n" /*MSGd*/
		"LSR 			R3, 	R3, 	#28;              \n"
		"AND 			R2, 	r6, 	0x0000000f;              \n" /*MSGg*/
		
		"EOR 			R4, 	r4, 	R3;              \n" /*first XOR (MSGd and RKi)*/
		"ldrb          r4,      [r8, R4];              \n" /* r4=sbox(r4)     */
		
		"EOR 			R4, 	r4, 	R2;              \n" /*first XOR (MSGg and sbox)*/
		
		"LSR 			R6, 	R6, 	#4;              \n"/*update left register of MSG*/
		"LSL 			R4, 	R4, 	#28;              \n"
		"ORR 			R6, 	R6, 	R4;              \n"/*newMSGg*/
		
		"ROR 			R7, 	R7, 	#28;              \n" /*update register of Round Key*/
		"ROR 			R5, 	R5, 	#28;              \n" /*update right register of MSG*/
		
		
		
		"ADD r12, r12, #1		\n"
		"CMP r12, #8		\n"
		"BNE NLL		\n"
        /*--------------------------------------------------------------------*/
        /* ----- LINEAR + NON LINEAR LAYER 								----- */
        /*--------------------------------------------------------------------*/
		"ROR R6, R6, #4 \n"/*update left register of MSG*/
		
		"AND R3, R5, 0xf0000000 \n"/*MSGd*/
		"LSR R3, r3, #28\n"
		
		"MOV R12, #0\n"
        
"LL1:	\n"
		"AND R2, R6, 0x0000000f \n"/*MSGg*/
		
		"EOR R2, R2, R3 \n"/* XOR MSGd MSGg*/
		
		"LSR R6, r6, #4 \n"/*update left register of MSG*/
		"LSL R2, r2, #28\n"
		"ORR R6, R6, R2 \n"/*newMSGg*/
		
		"ADD r12, r12, #1\n"
		"CMP r12, #7\n"
		"BNE LL1\n"
			
		
		"AND R2, R6, 0xf0000000\n" /*MSGg	*/
	
		"ROR R5, R5, #28 \n"/*update right register of MSG*/
	
		"MOV r12, #0\n"
			
		"LL2:	\n"
		"AND R3, R5, 0xf0000000 \n"/*MSGd	*/		
		
		"EOR R2, R2, R3\n" /* XOR MSGd MSGg */
		
		"ROR R5, R5, #28\n" /*update right register of MSG*/
		
		"ADD r12, r12, #1\n"
		"CMP r12, #6\n"
		"BNE LL2\n"
		"ROR R5, R5, #28 \n"
		
		"AND R6, R6, 0x0fffffff\n"
		"ORR R6, R6, R2\n"
		
		/*--------------------------------------------------------------------*/
		"subs          r11,            r11,           #1;\n"
        "beq           encrypt_add_last_round;         \n"
        
		/*--------------------------------------------------------------------*/
        /* Permutation Layer                                                        */
        /*--------------------------------------------------------------------*/
        "LDR r4, =(0x0fff0000)\n"
		"AND r10, R5, r4\n"
		"LSR r10, #8\n"
		
		"LDR r4, =(0xf00000f0)\n"
		"AND R3, R5, r4\n"
		"ORR r10, r10, R3\n"
		
		"LDR r4, =(0x0000000f)\n"
		"AND R3, R5, r4\n"
		"LSL R3, #20\n"
		"ORR r10, r10, R3\n"
		
		"LDR r4, =(0x00000f00)\n"
		"AND R3, R5, r4\n"
		"LSL R3, #16\n"
		"ORR r10, r10, R3\n"
		
		"LDR r4, =(0x0000f000)\n"
		"AND R3, R5, r4\n"
		"LSR R3, #12\n"
		"ORR r10, r10, R3\n"
		
		
		
		
		"LDR r4, =(0x000000ff)\n"
		"AND r2, R6, r4\n"
		"LSL r2, #16\n"
		
		"LDR r4, =(0xf0000000)\n"
		"AND R3, R6, r4\n"
		"ORR r2, r2, R3\n"
		
		"LDR r4, =(0x00f00f00)\n"
		"AND R3, R6, r4\n"
		"LSL R3, #4\n"
		"ORR r2, r2, R3\n"
		
		"LDR r4, =(0x000ff000)\n"
		"AND R3, R6, r4\n"
		"LSR R3, #8\n"
		"ORR r2, r2, R3\n"
		
		"LDR r4, =(0x0f000000)\n"
		"AND R3, R6, r4\n"
		"LSR R3, #24\n"
		"ORR r2, r2, R3\n"
		
		"mov r5, r2\n"
		"mov r6, r10\n"
		
		
		
        /*--------------------------------------------------------------------*/
        "b             encrypt_round_loop;             \n"
        
"encrypt_add_last_round:                               \n"
        /*--------------------------------------------------------------------*/
        /* Store state                                                        */
        /*--------------------------------------------------------------------*/
        "and 		  r3,       r6, 	0xf0000000;              \n"
        "lsr 		  r3,       r3, 	#4;              \n"
        
        "and 		  r4,       r6, 	0x0f000000;              \n"
        "lsr 		  r4,       r4, 	#8;              \n"
        "orr 		  r3,       r3, 	r4;              \n"
        
        "and 		  r4,       r6, 	0x00f00000;              \n"
        "lsr 		  r4,       r4, 	#12;              \n"
        "orr 		  r3,       r3, 	r4;              \n"
        
        "and 		  r4,       r6, 	0x000f0000;              \n"
        "lsr 		  r4,       r4, 	#16;              \n"
        "orr 		  r3,       r3, 	r4;              \n"
        
        
        
        "and 		  r2,       r6, 	0x0000f000;              \n"
        "lsl 		  r2,       r2, 	#12;              \n"
        
        "and 		  r4,       r6, 	0x00000f00;              \n"
        "lsl 		  r4,       r4, 	#8;              \n"
        "orr 		  r2,       r2, 	r4;              \n"
        
        "and 		  r4,       r6, 	0x000000f0;              \n"
        "lsl 		  r4,       r4, 	#4;              \n"
        "orr 		  r2,       r2, 	r4;              \n"
        
        "and 		  r4,       r6, 	0x0000000f;              \n"
        "orr 		  r2,       r2, 	r4;              \n"
        
        
        
        
        "and 		  r1,       r5, 	0xf0000000;              \n"
        "lsr 		  r1,       r1, 	#4;              \n"
        
        "and 		  r4,       r5, 	0x0f000000;              \n"
        "lsr 		  r4,       r4, 	#8;              \n"
        "orr 		  r1,       r1, 	r4;              \n"
        
        "and 		  r4,       r5, 	0x00f00000;              \n"
        "lsr 		  r4,       r4, 	#12;              \n"
        "orr 		  r1,       r1, 	r4;              \n"
        
        "and 		  r4,       r5, 	0x000f0000;              \n"
        "lsr 		  r4,       r4, 	#16;              \n"
        "orr 		  r1,       r1, 	r4;              \n"
        
        
        
        "and 		  r0,       r5, 	0x0000f000;              \n"
        "lsl 		  r0,       r0, 	#12;              \n"
        
        "and 		  r4,       r5, 	0x00000f00;              \n"
        "lsl 		  r4,       r4, 	#8;              \n"
        "orr 		  r0,       r0, 	r4;              \n"
        
        "and 		  r4,       r5, 	0x000000f0;              \n"
        "lsl 		  r4,       r4, 	#4;              \n"
        "orr 		  r0,       r0, 	r4;              \n"
        
        "and 		  r4,       r5, 	0x0000000f;              \n"
        "orr 		  r0,       r0, 	r4;              \n"
        
        
        
        "ldmia        sp!,             {r4};           \n"
        "stmia         r4,          {r0-r3};           \n"
        /*--------------------------------------------------------------------*/
        /* Restore registers                                                  */
        /*--------------------------------------------------------------------*/
        "ldmia        sp!,      {r0-r12,lr};           \n" /*                 */
        /*--------------------------------------------------------------------*/
    :
    : [block] "r" (block), [roundKeys] "r" (roundKeys) 
); 
}




#else

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	
	uint8_t i;

  
  /*29 rounds */
  for(i = 0 ; i < 29 ; i++)
  {

    
    /* NonLinearLayer + LinearLayer */
    
    block[8]  ^= (READ_SBOX_BYTE( S[block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 0])])) ;
    block[9]  ^= (READ_SBOX_BYTE( S[block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 1])]) ^ block[7]);
    block[10] ^= (READ_SBOX_BYTE (S[block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 2])]) ^ block[7]);
    block[11] ^= (READ_SBOX_BYTE (S[block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 3])]) ^ block[7]);
    block[12] ^= (READ_SBOX_BYTE( S[block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 4])]) ^ block[7]);
    block[13] ^= (READ_SBOX_BYTE( S[block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 5])]) ^ block[7]);
    block[14] ^= (READ_SBOX_BYTE( S[block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 6])]) ^ block[7]);
    block[15] ^= (READ_SBOX_BYTE( S[block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 7])]) ^ block[7] ^ block[6] ^ block[5] ^ block[4] ^ block[3] ^ block[2] ^ block[1]);
    
    
    /* PermutationLayer */
	uint8_t j; 
	uint8_t tmp[16];
	for(j = 0 ; j < 16 ; j++)
	tmp[ READ_SBOX_BYTE(P[j]) ] = block[j];

	for(j = 0 ; j < 16 ; j++)
	block[j] = tmp[j];
	
  } /* end round  */

  
  /* last round */
    

  block[8]  ^= (READ_SBOX_BYTE( S[block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 0])]));
  block[9]  ^= (READ_SBOX_BYTE( S[block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 1])]) ^ block[7]);
  block[10] ^= (READ_SBOX_BYTE( S[block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 2])]) ^ block[7]);
  block[11] ^= (READ_SBOX_BYTE( S[block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 3])]) ^ block[7]);
  block[12] ^= (READ_SBOX_BYTE( S[block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 4])]) ^ block[7]);
  block[13] ^= (READ_SBOX_BYTE( S[block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 5])]) ^ block[7]);
  block[14] ^= (READ_SBOX_BYTE( S[block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 6])]) ^ block[7]);
  block[15] ^= (READ_SBOX_BYTE( S[block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 7])]) ^ block[7] ^ block[6] ^ block[5] ^ block[4] ^ block[3] ^ block[2] ^ block[1]);
  
	
}

#endif
#endif
#endif

/*
 *
 * National Security Research Institute
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 National Security Research Institute
 *
 * Written in 2015 by Youngjoo Shin <yjshin@nsr.re.kr>
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

#if defined(MSP)
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
    uint8_t rot[3] = {23, 5, 3};
    uint8_t *prot = rot;

	asm volatile (\
		".include \"./../source/msp_rotate.s\"        \n"

		".macro SUBR X0h,X0l,X1h,X1l,K0,K1            \n"
		"   mov.b @r10+, \\K0                         \n"
		"rot_loop:                                    \n"
		"   ROL1 \\X1h,\\X1l                          \n"
		"   dec \\K0                                  \n"
		"   jnz rot_loop                              \n"

		"   mov %[roundKeys], r15                     \n"
		"   add r9, r15                               \n"
		"   mov @r15+, \\K0                           \n"
		"   mov @r15+, \\K1                           \n" 
		"   xor \\X0l, \\K0                           \n"
		"   xor \\X0h, \\K1                           \n"
		"   sub  \\K0, \\X1l                          \n"
		"   subc \\K1, \\X1h                          \n"
		"   mov %[roundKeys], r15                     \n"
		"   xor @r15+,\\X1l                           \n"
		"   xor @r15+,\\X1h                           \n" 
		".endm                                        \n"

		"   add #-16, %[roundKeys]                    \n"
		"   mov %[block], r14                         \n"   

		" push r4\n"
		" push r5\n"
		" push r6\n"
		" push r7\n"
		" push r8\n"
		" push r9\n"
		" push r10\n"
		" push r11\n"
		" push r12\n"
		" push r13\n"
		" add #20, r1\n"

		"   mov #72, r8                               \n"
		"init:                                        \n"
		"   clr r9                                    \n"
		"   mov %[rot], r10                           \n"
		/* advance the pointer of roundKeys by 16 bytes */
		"   add #16, %[roundKeys]                     \n"
		"loop:                                        \n" 
		"   cmp #12, r9                               \n"
		"   jz init                                   \n"
		"   incd r9                                   \n"
		"   incd r9                                   \n"

		/* load ciphertext */
		"   mov 12(r14),r4                            \n"
		"   mov 14(r14),r5                            \n"
		"   mov 0(r14),r6                             \n"
		"   mov 2(r14),r7                             \n"
		/* run subround */
		"   SUBR r5,r4,r7,r6,r12,r13                  \n"
		/* permute variables*/
		"   mov r6,12(r14)                            \n"
		"   mov r7,14(r14)                            \n"
		"   mov 4(r14),0(r14)                         \n"
		"   mov 6(r14),2(r14)                         \n"
		"   mov 8(r14),4(r14)                         \n"
		"   mov 10(r14),6(r14)                        \n"
		"   mov r4,8(r14)                             \n"
		"   mov r5,10(r14)                            \n"
		"loop2:                                       \n"
		"   dec r8                                    \n"
		"   jnz loop                                  \n"

		" add #-20, r1\n"
		" pop r13\n"
		" pop r12\n"
		" pop r11\n"
		" pop r10\n"
		" pop r9\n"
		" pop r8\n"
		" pop r7\n"
		" pop r6\n"
		" pop r5\n"
		" pop r4\n"
		:
		: [block] "m" (block), [roundKeys] "m" (roundKeys), [rot] "m" (prot)
	); 
}

#else
#include "primitives.h"

#define RK(x, y) READ_ROUND_KEY_DOUBLE_WORD(x[y])

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t* blk = (uint32_t*) block;
	uint32_t* rk = (uint32_t*) roundKeys;	
	uint32_t tmp;
	int8_t i;
	
	uint32_t b0 = blk[0];
	uint32_t b1 = blk[1];
	uint32_t b2 = blk[2];
	uint32_t b3 = blk[3];
	
	for (i = NUMBER_OF_ROUNDS - 1, rk += 92; i >= 0; --i, rk -= 4) {
		b0 = (rotr(b0, 9) - (b3 ^ RK(rk, 0))) ^ RK(rk, 1);
		b1 = (rotl(b1, 5) - (b0 ^ RK(rk, 2))) ^ RK(rk, 1);
		b2 = (rotl(b2, 3) - (b1 ^ RK(rk, 3))) ^ RK(rk, 1);
		
		tmp = b3;
		b3 = b2;
		b2 = b1;
		b1 = b0;
		b0 = tmp;
	}
	
	blk[0] = b0;
	blk[1] = b1;
	blk[2] = b2;
	blk[3] = b3;
}

#endif
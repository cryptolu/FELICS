/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 8-bit AVR ATMega 128, Fast speed code (C+ASM)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

// AVR low level assembly instructions
#ifdef WIN32
static uint8_t carry = 0;
#define LSL(var) do{ carry = var>>7, var <<= 1; }while(0)
#define LSR(var) do{ carry = var&1, var >>= 1; }while(0)
#define ROL(var) do{ carry |= (var>>6)&2, var = (var<<1)|(carry&1), carry>>=1; }while(0)
#define ROR(var) do{ carry |= (var<<1)&2, var = (var>>1)|(carry<<7), carry>>=1; }while(0)
#else
#define LSL(var) __asm__ __volatile__("lsl    %0 \n\t" : "+r" (var))
#define LSR(var) __asm__ __volatile__("lsr    %0 \n\t" : "+r" (var))
#define ROL(var) __asm__ __volatile__("rol    %0 \n\t" : "+r" (var))
#define ROR(var) __asm__ __volatile__("ror    %0 \n\t" : "+r" (var))
#endif


void grain_auth(GrainState * g, uint8_t msg)
{	uint8_t i, z;
	uint8_t r0, r1, r2, r3, r4, r5, r6, r7;
	uint8_t a0, a1, a2, a3, a4, a5, a6, a7;
	r0 = g->R[0], r1 = g->R[1], r2 = g->R[2], r3 = g->R[3], 
	r4 = g->R[4], r5 = g->R[5], r6 = g->R[6], r7 = g->R[7];
	a0 = g->A[0], a1 = g->A[1], a2 = g->A[2], a3 = g->A[3], 
	a4 = g->A[4], a5 = g->A[5], a6 = g->A[6], a7 = g->A[7];
	z = g->z1;

	for(i=0; i<8; ++i)
	{	uint8_t mask = -(msg & 1);
		msg >>=1;
		a7 ^= r7 & mask;
		a6 ^= r6 & mask;
		a5 ^= r5 & mask;
		a4 ^= r4 & mask;
		a3 ^= r3 & mask;
		a2 ^= r2 & mask;
		a1 ^= r1 & mask;
		a0 ^= r0 & mask;
		LSR(z); ROR(r7); ROR(r6); ROR(r5); ROR(r4); ROR(r3); ROR(r2); ROR(r1); ROR(r0);
	}

	g->R[0] = r0, g->R[1] = r1, g->R[2] = r2, g->R[3] = r3, 
	g->R[4] = r4, g->R[5] = r5, g->R[6] = r6, g->R[7] = r7;
	g->A[0] = a0, g->A[1] = a1, g->A[2] = a2, g->A[3] = a3, 
	g->A[4] = a4, g->A[5] = a5, g->A[6] = a6, g->A[7] = a7;
}


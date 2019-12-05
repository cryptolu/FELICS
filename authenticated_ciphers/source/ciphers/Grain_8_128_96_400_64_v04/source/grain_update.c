/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 16-bit MSP430F1611, Fast speed code (C+ASM)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

#if !defined(IS_MSP)
#if (defined(MSP)||defined(__MSP__))
#define IS_MSP 1
#else
#define IS_MSP 0
#endif
#endif


#if IS_MSP == 0

#define get8(B, A, R)\
	R = B & 0x00ff;	\
	R |= A & 0xff00;\
	R = (R>>8)|(R<<8);

static uint16_t C = 0, newC;

#define shr(t)\
	newC = t & 1;\
	t = (t>>1)|(C<<15);\
	C = newC;

#define shl(t)\
	newC = t>>15;\
	t = (t<<1)|C;\
	C = newC;

uint16_t stack[5], stack_ptr = 0;

#define push(x) stack[stack_ptr++] = x;
#define pop(x) x = stack[--stack_ptr];
#define mov(a, b)	a = b;
#define xor(a, b)	a^=b;
#define and(a, b)	a&=b;
#define swap(a)		a = (a<<8)|(a>>8);

#define PTR(i)  *(uint16_t*)(((uint8_t*)g->lfsr) + i)

#else

#define get8(B, A, R)				\
		"mov.b	" B " , " R "  \n\t"\
		"xor.b	" A " , " R "  \n\t"\
		"xor	" A " , " R "  \n\t"\
		"swpb	" R "  \n\t"	\

#define shr(T0)\
		"rrc	" T0 " 	\n\t"	\

#define shl(T0)	\
		"rlc	" T0 " 	\n\t"	\

#define PTR(i) #i "(%11)"

#define mov(A, B)	"mov " B " , " A "  \n\t" 
#define xor(A, B)	"xor " B " , " A "  \n\t" 
#define and(A, B)	"and " B " , " A "  \n\t" 
#define push(A)		"push " A "  \n\t"
#define pop(A)		"pop " A "  \n\t"
#define swap(A)		"swpb " A "  \n\t"

#endif


uint16_t grain_update(GrainState * g)
{	
	/* Can only use at most 12 registers: t0..t7, a..d, pointer g */
	uint16_t t0, t1, t2, t3, t4, t5, t6;
	uint16_t a, b, c, d;

#if IS_MSP == 1
#define t0	"%0"
#define t1	"%1"
#define t2	"%2"
#define t3	"%3"
#define t4	"%4"
#define t5	"%5"
#define t6	"%6"
#define a	"%7"
#define b	"%8"
#define c	"%9"
#define d	"%10"

__asm__ __volatile__(
#endif

	mov(t0, PTR(0))
	mov(t1, PTR(2))
	mov(t2, PTR(4))
	mov(t3, PTR(6))
	mov(t4, PTR(8))
	mov(t5, PTR(10))
	mov(t6, PTR(12))
	mov(PTR(0), t1)
	mov(PTR(2), t2)
	mov(PTR(4), t3)
	mov(PTR(6), t4)
	mov(PTR(8), t5)
	mov(PTR(10), t6)
	mov(PTR(12), PTR(14))
	mov(c, t2)
	xor(c, t4)
	mov(d, t3)
	xor(d, t5)
	shl(c) shl(d)
	xor(c, t0)
	xor(d, t1)
	shl(c) shl(d)
	get8(d, c, a)
	xor(a, t0)
	xor(a, t6)
	mov(b, t5)
	mov(c, t6)
	shr(c) shr(b)
	xor(a, b)
	mov(PTR(14), a)
	mov(a, t1)
	mov(b, t2)
	get8(b, a, b)
	swap(a)
	shl(a) shl(b)
	and(a, t0)
	and(b, t1)
	xor(a, t5)
	xor(b, t6)
	shl(t2) shl(t3) shl(t4) shl(t5) shl(t6)
	shl(t2) shl(t3) shl(t4)
	shl(t2) shl(t3) shl(t4)
	shl(t2) shl(t3) shl(t4)
	shl(a) shl(b)
	shl(a) shl(b)
	shl(a) shl(b)
	and(t4, t5)
	xor(b, t4)
	mov(a, t0)
	mov(c, PTR(26))
	mov(d, PTR(28))
	shl(t2) shl(t3)
	and(t2, c)
	and(t3, d)
	and(t5, c)
	and(t6, d)
	xor(a, d)
	shl(c) shl(d)
	mov(t4, d)
	shl(c) shl(d)
	shl(c) shl(d)
	and(t4, d)
	shl(c) shl(d)
	and(t4, d)
	shl(c) shl(d)
	xor(a, d)
	shl(c) shl(d)
	shl(c) shl(d)
	xor(b, d)
	shl(c) shl(d)
	and(t4, d)
	xor(a, t4)
	mov(c, PTR(16))
	mov(d, PTR(18))
	xor(a, c)
	get8(t1, t0, t1)
	mov(t0, c)
	mov(t4, d)
	shl(c) shl(d)
	xor(b, d)
	shl(c) shl(d)
	shl(c) shl(d)
	and(t5, c)
	and(t6, d)
	xor(t5, t2)
	xor(t6, t3)
	shl(t5) shl(t6)
	xor(b, t6)
	mov(t5, d)
	shl(c) shl(d)
	and(t1, d)
	xor(b, t1)
	shl(c) shl(d)
	and(t5, d)
	xor(a, t5)
	
#if 0 /* The original second part to implement */
	// !!! t0=NF(0), t4=NF(2)

	// e=14 o=11
	y ^= (NF(0)>>2) ^ (NF(4)>>4) ^ NF(8);
	y ^= (NF(5)>>5) ^ (NF(9)>>1);

	// only NF and stacked values
	nn ^= (NF(0)>>3) & (NF(8)>>3);
	nn ^= (NF(2)>>1) & (NF(2)>>2);
	nn ^= (NF(8)>>4) & (NF(10)>>4);

	nn ^= ((NF(3)>>3) & (NF(7)>>3)) ^ (NF(3)>>2) ^ NF(7);

	nn ^= NF(5) & NF(6);
	nn ^= (NF(7)>>5) & (NF(8)>>1);
	nn ^= (NF(2)>>6) &    (NF(3)>>1) & NF(3);
	nn ^= (NF(8)>>6) & (NF(9)>>6) & (NF(10)>>2);

	nn ^= a;
	y ^= b;

	memcpy(g->nfsr, g->nfsr + 1, 14);
	g->nfsr[7] = nn;
	return y;
#endif

	mov(t3, PTR(19))
	mov(t2, PTR(20))
	mov(t5, PTR(21))
	mov(t6, PTR(22))
	mov(PTR(16), t4)
	mov(PTR(18), t2)
	mov(PTR(20), t6)
	mov(t1, t5)
	and(t1, t6)
	xor(a, t1)
	mov(t1, t6)
	swap(t1)
	shr(t6) shr(t2) shr(t4) shr(t0)
	mov(c, t3)
	mov(d, t4)
	shr(t1) shr(t5) shr(t3)
	and(c, t3)
	shr(t6) shr(t2) shr(t4) shr(t0)
	xor(b, t0)
	and(d, t4)
	xor(a, d)
	shr(t1) shr(t5) shr(t3)
	xor(a, t3)
	shr(t6) shr(t2) shr(t4) shr(t0)
	mov(d, t0)
	shr(t1) shr(t5) shr(t3)
	shr(t6) shr(t2) shr(t4) shr(t0)
	xor(b, t2)
	shr(t2) shr(t4)
	shr(t2) shr(t4)
	and(c, t4)
	xor(a, c)
	shr(t1) shr(t5)
	shr(t1) shr(t5)
	xor(b, t5)
	mov(t0, PTR(23))
	mov(t4, PTR(25))
	mov(t2, PTR(27))
	xor(a, t0)
	shr(t2) shr(t4) shr(t0)
	xor(b, t4)
	shr(t2) shr(t4) shr(t0)
	shr(t2) shr(t4) shr(t0)
	and(t3, t0)
	xor(a, t3)
	shr(t2) shr(t4) shr(t0)
	shr(t2) shr(t4) shr(t0)
	shr(t2) shr(t4)
	mov(t1, PTR(24))
	mov(t3, PTR(26))
	mov(t5, PTR(28))
	mov(PTR(22), t1)
	mov(PTR(24), t3)
	mov(PTR(26), t5)
	mov(PTR(28), PTR(30))
	xor(b, t1)
	shr(t5) shr(t3) shr(t1)
	and(t0, t1)
	xor(a, t0)
	shr(t5) shr(t3) shr(t1)
	and(t4, t3)
	shr(t5) shr(t3) shr(t1)
	and(d, t1)
	xor(a, d)
	shr(t5) shr(t3) shr(t1)
	mov(t0, t1)
	and(t0, t3)
	xor(a, t0)
	shr(t3) shr(t1)
	shr(t3) shr(t1)
	and(t4, t1)
	xor(a, t4)
	mov(PTR(30), a)

#if IS_MSP == 1
#undef t0
#undef t1
#undef t2
#undef t3
#undef t4
#undef t5
#undef t6
#undef a
#undef b
#undef c
#undef d

	: "=r" (t0), "=r" (t1), "=r" (t2), "=r" (t3), "=r" (t4), "=r" (t5), "=r" (t6), "=r" (a), "=r" (b), "=r" (c), "=r" (d), "+r" (g)
	);
#endif
	return b;
}

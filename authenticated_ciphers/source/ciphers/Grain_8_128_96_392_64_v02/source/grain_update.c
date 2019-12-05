/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 8-bit AVR ATMega 128, Fast speed code (C+ASM)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

#if defined(AVR) || defined(__AVR__)
#define IS_AVR 1
#else
#define IS_AVR 0
#endif

// In case of AVR platform => use builting assembly code
#if IS_AVR
#define xstr(s) str(s)
#define str(s) #s
#define R(i) "%" xstr(i)
#define LFSR(i) "%a21+" xstr(i)
#define NFSR(i) "%a21+16+" xstr(i)

#define ldd(out, in)	"ldd " out ", " in " \n\t"
#define std(out, in)	"std " out ", " in " \n\t"
#define mov(out, in)	"mov " out ", " in " \n\t"
#define xor(out, in)	"eor " out ", " in " \n\t"
#define and(out, in)	"and " out ", " in " \n\t"
#define rol(var)		"rol " var " \n\t"
#define ror(var)		"ror " var " \n\t"

#else
// Otherwise, emulate AVR instructions so that we can test the code
static uint8_t CR = 0, TREG;
#define ldd(out, in)	out = in;
#define std(out, in)	out = in;
#define mov(out, in)	out = in;
#define xor(out, in)	out ^= in;
#define and(out, in)	out &= in;
#define rol(var) CR |= (var>>6)&2, var = (var<<1)|(CR&1), CR>>=1;
#define ror(var) CR |= (var<<1)&2, var = (var>>1)|(CR<<7), CR>>=1;
#define LFSR(i)	g->lfsr[i]
#define NFSR(i)	g->nfsr[i]
#define R(i) r##i
#endif


uint8_t grain_update(GrainState * g)
{	
	uint8_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20;

#if IS_AVR
	__asm__ __volatile__(
#endif

	/* NOTE: the instruction 'movw' not used in the code below, 
	         but it could be highly efficient in AVR! Worth trying.
	*/
	ldd(R(0), LFSR(0))	
	ldd(R(1), LFSR(1))	
	ldd(R(2), LFSR(2))	
	ldd(R(3), LFSR(3))
	ldd(R(4), LFSR(4))	
	ldd(R(5), LFSR(5))	
	ldd(R(6), LFSR(6))	
	ldd(R(7), LFSR(7))
	ldd(R(8), LFSR(8))	
	ldd(R(9), LFSR(9))	
	ldd(R(10), LFSR(10))	
	ldd(R(11), LFSR(11))
	ldd(R(12), LFSR(12))	
	std(LFSR(0), R(1))	
	std(LFSR(1), R(2))	
	std(LFSR(2), R(3))
	std(LFSR(3), R(4))	
	std(LFSR(4), R(5))	
	std(LFSR(5), R(6))	
	std(LFSR(6), R(7))
	std(LFSR(7), R(8))	
	std(LFSR(8), R(9))	
	std(LFSR(9), R(10))	
	std(LFSR(10), R(11))
	std(LFSR(11), R(12))	
	ldd(R(13), LFSR(13))	
	std(LFSR(12), R(13))	
	ldd(R(13), LFSR(14))
	std(LFSR(13), R(13))	
	ldd(R(13), LFSR(15))	
	std(LFSR(14), R(13))

	mov(R(16), R(0))	
	xor(R(16), R(12))	
	mov(R(19), R(0))	
	mov(R(17), R(5))	
	mov(R(14), R(6))
	ror(R(14)) ror(R(17)) 
	ror(R(14)) ror(R(17))
	mov(R(13), R(10)) 
	mov(R(14), R(11))
	ror(R(14)) ror(R(13))
	xor(R(16), R(13))	
	mov(R(14), R(1))
	rol(R(0)) rol(R(1)) rol(R(2)) rol(R(3)) 
	rol(R(4)) rol(R(5)) rol(R(7)) rol(R(8)) 
	rol(R(9)) rol(R(10)) rol(R(11)) rol(R(12))
	xor(R(16), R(1))	
	mov(R(13), R(10))
	rol(R(1)) rol(R(2)) rol(R(3)) rol(R(4)) 
	rol(R(5)) rol(R(7)) rol(R(8)) rol(R(9)) 
	rol(R(11)) rol(R(12))
	mov(R(15), R(12))	
	xor(R(16), R(5))	
	xor(R(16), R(9))
	std(LFSR(15), R(16))
	rol(R(1)) rol(R(2)) rol(R(3)) rol(R(7)) 
	rol(R(8)) rol(R(11)) rol(R(12))
	mov(R(16), R(2))	
	mov(R(20), R(12))
	rol(R(2)) rol(R(3)) rol(R(7)) rol(R(8))
	and(R(16), R(3))	
	xor(R(20), R(16))	
	and(R(13), R(8))	
	xor(R(20), R(13))
	
	ldd(R(0), NFSR(0))	
	ldd(R(1), NFSR(1))	
	ldd(R(2), NFSR(2))	
	ldd(R(3), NFSR(3))
	ldd(R(4), NFSR(4))	
	ldd(R(5), NFSR(5))	
	ldd(R(6), NFSR(6))	
	ldd(R(7), NFSR(7))
	ldd(R(8), NFSR(8))	
	ldd(R(9), NFSR(9))	
	ldd(R(10), NFSR(10))	
	ldd(R(11), NFSR(11))
	ldd(R(12), NFSR(12))	
	std(NFSR(0), R(1))	
	std(NFSR(1), R(2))	
	std(NFSR(2), R(3))
	std(NFSR(3), R(4))	
	std(NFSR(4), R(5))	
	std(NFSR(5), R(6))	
	std(NFSR(6), R(7))
	std(NFSR(7), R(8))	
	std(NFSR(8), R(9))	
	std(NFSR(9), R(10))	
	std(NFSR(10), R(11))
	std(NFSR(11), R(12))	
	ldd(R(13), NFSR(13))	
	std(NFSR(12), R(13))	
	ldd(R(13), NFSR(14))
	std(NFSR(13), R(13))	
	ldd(R(13), NFSR(15))	
	std(NFSR(14), R(13))

	mov(R(13), R(11))	
	mov(R(16), R(12))
	rol(R(13)) rol(R(16))
	and(R(17), R(16))	
	xor(R(20), R(17))	
	and(R(15), R(16))	
	mov(R(13), R(5))	
	and(R(13), R(6))
	xor(R(19), R(0))	
	xor(R(19), R(7))	
	xor(R(19), R(12))	
	xor(R(19), R(13))	
	xor(R(20), R(8))	
	mov(R(13), R(3))	
	and(R(16), R(11))
	ror(R(12)) ror(R(11)) ror(R(10)) ror(R(9)) 
	ror(R(8)) ror(R(7)) ror(R(6)) ror(R(5)) 
	ror(R(4)) ror(R(3)) ror(R(2)) ror(R(1)) ror(R(0))
	and(R(13), R(3))	
	xor(R(20), R(9))	
	xor(R(20), R(11))	
	mov(R(17), R(2))	
	mov(R(18), R(8))
	ror(R(12)) ror(R(11)) ror(R(10)) ror(R(9)) 
	ror(R(8)) ror(R(7)) ror(R(6)) ror(R(5)) 
	ror(R(4)) ror(R(3)) ror(R(2)) ror(R(1)) ror(R(0))
	and(R(17), R(2))	
	xor(R(19), R(17))	
	xor(R(20), R(0))	
	xor(R(19), R(3))	
	mov(R(17), R(10))
	ror(R(12)) ror(R(11)) ror(R(10)) ror(R(9)) 
	ror(R(8)) ror(R(7)) ror(R(6)) ror(R(5)) 
	ror(R(4)) ror(R(3)) ror(R(2)) ror(R(1)) ror(R(0))
	and(R(0), R(8))		
	xor(R(19), R(0))	
	mov(R(0), R(3))		
	and(R(0), R(7))		
	xor(R(19), R(0))
	mov(R(0), R(1))		
	xor(R(19), R(11))
	ror(R(12)) ror(R(11)) ror(R(10)) ror(R(9)) 
	ror(R(8)) ror(R(7)) ror(R(6)) ror(R(5)) 
	ror(R(4)) ror(R(3)) ror(R(2)) ror(R(1))
	and(R(15), R(1))	
	xor(R(20), R(15))	
	and(R(14), R(1))	
	xor(R(20), R(14))	
	and(R(16), R(11))
	xor(R(20), R(4))	
	mov(R(14), R(8))	
	and(R(14), R(10))	
	xor(R(19), R(14))
	ror(R(12)) ror(R(11)) ror(R(10)) ror(R(9)) 
	ror(R(8)) ror(R(7)) ror(R(6)) ror(R(5)) 
	ror(R(3)) ror(R(2)) ror(R(1))
	and(R(16), R(11))	
	xor(R(19), R(16))	
	and(R(18), R(7))	
	xor(R(19), R(18))	
	and(R(0), R(1))
	xor(R(19), R(0))	
	xor(R(20), R(5))
	ror(R(10)) ror(R(9)) ror(R(8)) ror(R(3)) 
	ror(R(2)) ror(R(1))
	and(R(13), R(2))	
	xor(R(19), R(13))	
	and(R(17), R(8))	
	and(R(17), R(9))	
	xor(R(19), R(17))
	ror(R(2)) ror(R(1))
	xor(R(20), R(1))	
	std(NFSR(15), R(19))
	
#if IS_AVR
	: "=r" (r0), "=r" (r1), "=r" (r2), "=r" (r3), "=r" (r4), "=r" (r5), "=r" (r6), "=r" (r7), "=r" (r8), "=r" (r9), "=r" (r10), "=r" (r11), "=r" (r12), "=r" (r13), "=r" (r14), "=r" (r15), "=r" (r16), "=r" (r17), "=r" (r18), "=r" (r19), "=r" (r20)
	: "b" (g)
	: "memory"
	);
#endif
	return r20;
}

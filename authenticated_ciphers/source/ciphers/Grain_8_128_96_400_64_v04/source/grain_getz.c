/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 16-bit MSP430F1611, Fast speed code (C+ASM)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

uint8_t grain_getz(GrainState * g)
{	uint16_t tmp, x = grain_update(g);

#if !(defined(MSP)||defined(__MSP__))
	tmp = (x ^ (x>>1)) & 0x2222; x ^= tmp ^ (tmp<<1); // a(Ab)Bc(Cd)De(Ef)Fg(Gh)H
	tmp = (x ^ (x>>2)) & 0x0c0c; x ^= tmp ^ (tmp<<2); // ab(ABcd)CDef(EFgh)GH
	tmp = (x ^ (x>>4)) & 0x00f0; x ^= tmp ^ (tmp<<4); // abcd(ABCDefgh)EFGH
#else
__asm__ __volatile__(
	"mov	%0, %1		\t\n"
	"rra	%1			\t\n"
	"xor	%0, %1		\t\n"
	"and	#8738, %1	\t\n"
	"xor	%1, %0		\t\n"
	"rla	%1			\t\n"
	"xor	%1, %0		\t\n"

	"mov	%0, %1		\t\n"
	"rra	%1			\t\n"
	"rra	%1			\t\n"
	"xor	%0, %1		\t\n"
	"and	#3084, %1	\t\n"
	"xor	%1, %0		\t\n"
	"rla	%1			\t\n"
	"rla	%1			\t\n"
	"xor	%1, %0		\t\n"

	"mov	%0, %1		\t\n"
	"rra	%1			\t\n"
	"rra	%1			\t\n"
	"rra	%1			\t\n"
	"rra	%1			\t\n"
	"xor	%0, %1		\t\n"
	"and	#240, %1	\t\n"
	"xor	%1, %0		\t\n"
	"rla	%1			\t\n"
	"rla	%1			\t\n"
	"rla	%1			\t\n"
	"rla	%1			\t\n"
	"xor	%1, %0		\t\n"

	: "+r"(x), "=r"(tmp)
	:
	);
#endif

	g->R[4] = x >> 8;
	return (uint8_t)x;
}

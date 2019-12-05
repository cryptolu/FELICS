/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 16-bit MSP430F1611, Small size code (C)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

uint8_t grain_getz(GrainState * g)
{	uint16_t tmp, x = grain_update(g);
	tmp = (x ^ (x>>1)) & 0x2222; x ^= tmp ^ (tmp<<1); // a(Ab)Bc(Cd)De(Ef)Fg(Gh)H
	tmp = (x ^ (x>>2)) & 0x0c0c; x ^= tmp ^ (tmp<<2); // ab(ABcd)CDef(EFgh)GH
	tmp = (x ^ (x>>4)) & 0x00f0; x ^= tmp ^ (tmp<<4); // abcd(ABCDefgh)EFGH
	g->R[4] = x >> 8;
	return (uint8_t)x;
}

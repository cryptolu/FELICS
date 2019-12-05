/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 8-bit AVR ATMega 128, Small size code
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

static uint8_t deinterleave(uint8_t x)
{	
	uint8_t tmp;
	tmp = (x ^ (x >> 1)) & 0x22; x ^= tmp ^ (tmp << 1); /* d(Dc)Cb(Ba)A -> d(cD)Cb(aB)A */
	tmp = (x ^ (x >> 2)) & 0x0c; x ^= tmp ^ (tmp << 2); /* dc(DCba)BA -> dc(baDC)BA */
	return x;
}

uint8_t grain_getz(GrainState * g)
{	uint8_t r0 = deinterleave(grain_update(g));
	uint8_t r1 = SWAP(deinterleave(grain_update(g)));
	uint8_t t = (r0 ^ r1) & 0xf0;
	g->z1 = SWAP(r1 ^ t);
	return r0 ^ t;
}

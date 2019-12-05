/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 8-bit AVR ATMega 128, Small size code
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

void Initialize(uint8_t *state, const uint8_t *key, const uint8_t *nonce)
{
	GrainState * g = (GrainState *)state;
	uint8_t i;

	memcpy(g->nfsr, key, 16);
	memcpy(g->lfsr, nonce, 12);
	g->lfsr[12] = g->lfsr[13] = g->lfsr[14] = 0xff;
	g->lfsr[15] = 0x7f;

	for(i=0; i<32; ++i)
	{	uint8_t y = grain_update(g);
		g->lfsr[15] ^= y;
		g->nfsr[15] ^= y;
	}
	
	for(i=0; i<16; ++i)
	{	g->A[i] = grain_update(g);
		g->lfsr[15] ^= key[i];
	}
}

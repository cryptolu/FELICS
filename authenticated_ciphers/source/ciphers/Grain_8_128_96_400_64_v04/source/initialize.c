/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 16-bit MSP430F1611, Fast speed code (C+ASM)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

void Initialize(uint8_t *state, const uint8_t *key, const uint8_t *nonce)
{
	GrainState * g = (GrainState *)state;
	uint16_t i;

	memcpy(g->nfsr, key, 16);
	memcpy(g->lfsr, nonce, 12);
	g->lfsr[6] = 0xffff;
	g->lfsr[7] = 0x7fff;

	for(i=0; i<16; ++i)
	{	uint16_t y = grain_update(g);
		g->lfsr[7] ^= y;
		g->nfsr[7] ^= y;
	}
	
	for(i=0; i<8; ++i)
	{	g->A[i] = grain_update(g);
		g->lfsr[7] ^= ((const uint16_t*)key)[i];
	}
	// g->R[4] = 0;
}

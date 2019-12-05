/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 8-bit AVR ATMega 128, Small size code
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

void grain_auth(GrainState * g, uint8_t msg)
{	uint8_t i;
	for(i=0; i<8; ++i)
	{	uint8_t j, mask = -(msg & 1);
		msg >>=1;
		for(j=0; j<8; ++j)
		{	g->A[j] ^= g->R[j] & mask;
			g->R[j] = (uint8_t)((*(uint16_t*)(g->R + j))>>1); /* force AVR to use LSR and ROR instructions */
		}
		g->z1 >>= 1;
	}
}

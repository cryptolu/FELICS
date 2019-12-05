/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 16-bit MSP430F1611, Small size code (C)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

void grain_auth(GrainState * g, uint8_t msg)
{	uint16_t i;
	for(i=0; i<8; ++i, g->R[4] >>= 1)
	{	uint16_t j, mask = -(uint16_t)(msg & 1);
		msg >>=1;
		for(j=0; j<4; ++j)
		{	g->A[j] ^= g->R[j] & mask;
			g->R[j] = (g->R[j]>>1) | (g->R[j+1]<<15);
		}
	}
}

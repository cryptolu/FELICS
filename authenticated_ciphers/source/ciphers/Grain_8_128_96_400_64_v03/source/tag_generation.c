/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 16-bit MSP430F1611, Small size code (C)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

void TagGeneration(uint8_t *state, uint8_t *tag)
{
	GrainState * g = (GrainState *)state;
	uint16_t i;
	for(i=0; i<4; ++i)
		((uint16_t*)tag)[i] = g->A[i] ^ g->R[i];
}

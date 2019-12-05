/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 8-bit AVR ATMega 128, Fast speed code (C+ASM)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

void TagGeneration(uint8_t *state, uint8_t *tag)
{
	GrainState * g = (GrainState *)state;
	// Alt1: grain_auth(g, 1); memcpy(tag, g->A, 8);
	// Alt2: *(uint64_t*)tag = (*(uint64_t*)g->A) ^ (*(uint64_t*)g->R);
	uint8_t i;
	for(i=0; i < 8; ++i)
		tag[i] = g->A[i] ^ g->R[i];
}

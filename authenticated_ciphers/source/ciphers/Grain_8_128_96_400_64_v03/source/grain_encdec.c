/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 16-bit MSP430F1611, Small size code (C)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

void grain_encdec(uint8_t *state, uint8_t *message, uint32_t message_length, uint8_t mask)
{
	GrainState * g = (GrainState *)state;
	while(message_length--)
	{	uint8_t z0 = grain_getz(g);
		*message ^= z0 & ~mask;
		grain_auth(g, *message);
		*message ^= z0 & mask;
		message++;
	}
}

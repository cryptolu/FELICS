/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 16-bit MSP430F1611, Fast speed code (C+ASM)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

void ProcessAssociatedData(uint8_t *state, uint8_t *associatedData, uint32_t associated_data_length)
{
	GrainState * g = (GrainState *)state;
	uint8_t k, der[5], der_len;
	*(uint32_t*)(der + 1) = associated_data_length;

	der[0] = 0x80;
	for(der_len=4; !der[der_len]; --der_len);

	/* Alt1: if(!((der[1] & 0x80) | (der_len>>1))) */
	/* Alt2: if(!((der_len>>1) | (der[1]>>7))) */
	/* Alt3: if(!((der_len & 0xfe)|(der[1] & 0x80))) */
	if((der_len<=1) && (der[1]<128))
	{	der[0] = der[1];
		der_len = 0;
	}
	else
		der[0] |= der_len;

	for(k=0; k <= der_len; k++)
	{	grain_getz(g);
		grain_auth(g, der[k]);
	}

	while(associated_data_length--)
	{	grain_getz(g);
		grain_auth(g, *(associatedData));
		associatedData++;
	}
}

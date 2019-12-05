/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 8-bit AVR ATMega 128, Fast speed code (C+ASM)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

#include <string.h>

void ProcessAssociatedData(uint8_t *state, uint8_t *associatedData, uint32_t associated_data_length)
{
	GrainState * g = (GrainState *)state;
	uint8_t k, der[5], der_len;

#if 1
	// Determine DER length and fill-in der[] data
__asm__ __volatile(
	"std	%a3+1, %A2	\t\n"
	"std	%a3+2, %B2	\t\n"
	"std	%a3+3, %C2	\t\n"
	"std	%a3+4, %D2	\t\n"
	"ldi	%0, 4	\t\n"
	"cpi	%D2, 0	\t\n"
	"brne	1f	\t\n"
	"subi	%0, 1	\t\n"
	"cpi	%C2, 0	\t\n"
	"brne	1f	\t\n"
	"subi	%0, 1	\t\n"
	"cpi	%B2, 0	\t\n"
	"brne	1f	\t\n"
	"subi	%0, 1	\t\n"
	"cpi	%A2, 0	\t\n"
	"brne	1f	\t\n"
	"subi	%0, 1	\t\n"
	"1: \t\n"
	"cpi	%0, 2 \t\n"
	"brge	2f	\t\n"
	"bst	%A2, 7 \t\n"
	"brts	2f	\t\n"
	"ldi	%0, 0	\t\n"
	"std	%a3+0, %A2	\t\n"
	"brtc	3f	\t\n"
	"2: \t\n"
	"ldi	%1, 0x80	\t\n"
	"eor	%1, %0	\t\n"
	"std	%a3+0, %1	\t\n"
	"3: \t\n"
	: "+d" (der_len), "+d" (k)
	: "a" (associated_data_length), "b" (der)
	);
#else
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
#endif

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

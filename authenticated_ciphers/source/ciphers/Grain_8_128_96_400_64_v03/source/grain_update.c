/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 16-bit MSP430F1611, Small size code (C)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

static const uint8_t program16[54] = 
{	// program for LFSR update
	0x60, 0x51, 0x46, 0x26, 0x07, 0x00, 
	// program for NFSR update
	/*0x00,*/ 0x80, 0x9a, 0xb8, 0xdb, 0xe0, 0xd8, 0xdc, 0xdd, 0xdf, 0x96, 0x98, 0x99, 0xc6, 0xce, 0xd2, 
	0x83, 0xc3, 0x8b, 0x8d, 0x91, 0x92, 0x9b, 0xbb, 0xa8, 0xb0, 0xbd, 0xc1, 0xc4, 0xd4, 
	// program for y
	0x8c, 0x08, 0x0d, 0x14, 0xdf, 0x2a, 0x3c, 0x4f, 0x8c, 0xdf, 0x5e, 0x5d, 0x82, 0x8f, 0xa4, 0xad, 0xc0, 0xc9, 0xd9
};

// Mini-RISC CPU
static uint16_t execute_program(const uint16_t * data, uint16_t command, uint16_t pc, uint16_t pc_end)
{	uint16_t result = 0x0000, product = 0xffff;
	for(; pc < pc_end; ++pc, command>>=1)
	{	uint16_t offset = program16[pc] >> 4;
		uint16_t shift = program16[pc] & 15;
		product &= (uint16_t)(*((uint32_t*)(data + offset)) >> shift);
		if(command & 1) continue;
		result ^= product;
		product = 0xffff;
	}
	return result;
}

uint16_t grain_update(GrainState * g)
{	
	uint16_t nn, y, i;
	nn  = execute_program(g->lfsr, 0x6dc0, 5, 21);
	nn ^= execute_program(g->lfsr, 0x1555, 21, 35);
	y   = execute_program(g->lfsr, 0x0355, 35, 54);
	g->nfsr[0] = execute_program(g->lfsr, 0x0000, 0, 6);

	memcpy(g->lfsr, g->lfsr + 1, 30);
	g->nfsr[7] = nn;
	return y;
}

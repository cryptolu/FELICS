/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 8-bit AVR ATMega 128, Small size code
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

static const uint8_t program[52] = 
{	// program for LFSR update
	0x64, 0x68, 0x70, 0x1a, 0x0c, 0x00,
	/* program for NFSR update (the first 2 codes overlap with previous 2 codes => 2 bytes win) */
	/*0x0c, 0x00,*/ 0x07, 0xb3, 0x37, 0xe8, 0xe9, 0x2a, 0xc8, 0x4a, 0xb0, 0x38, 0x85, 0x06,	0x23, 
	0x3b, 0xb1, 0x51, 0x92, 0x22, 0xd7, 0x18, 0xe2, 0x83, 0x13, 0x8b, 0xcb, 0xdb, 0x7b,
	// program for y-NFSR
	0x55, 0x19, 0x1b, 0x20, 0x71, 0x44, 0x08,
	// program for y-LFSR
	0x5b, 0xd1, 0x42, 0xc7, 0x79, 0xcd, 0x01, 0xff, 0x25, 0xff, 0xcd, 0x6b
};

// Mini-RISC CPU
static uint8_t execute_program(const uint8_t * data, uint8_t pc, uint8_t pc_end)
{	uint8_t result = 0x00, product = 0xff;
	for(; pc<pc_end; ++pc)
	{	product &= (uint8_t)((*(uint16_t*)(data + (program[pc] & 0x0f))) >> (SWAP(program[pc]) & 7));
		if(program[pc] & 0x80) continue;
		result ^= product;
		product = 0xff;
	}
	return result;
}

uint8_t grain_update(GrainState * g)
{	uint8_t nn, y, i;
	uint16_t j;

	nn = g->lfsr[0] ^ execute_program(g->nfsr, 4, 4 + 29);
	y = execute_program(g->nfsr, 33, 33 + 7);
	i = g->lfsr[13];
	j = *(uint16_t*)(g->lfsr+14);
	*(uint16_t*)(g->lfsr+13) = *(uint16_t*)(g->nfsr+1);
	g->lfsr[15] = g->nfsr[11];
	g->nfsr[0] = g->nfsr[12];
	y ^= execute_program(g->lfsr, 40, 40 + 12);
	g->lfsr[13] = i;
	*(uint16_t*)(g->lfsr+14) = j;
	g->lfsr[16] = execute_program(g->lfsr, 0, 0 + 6);

	memcpy(g->lfsr, g->lfsr+1, 31);
	g->nfsr[15] = nn;
	return y;
}

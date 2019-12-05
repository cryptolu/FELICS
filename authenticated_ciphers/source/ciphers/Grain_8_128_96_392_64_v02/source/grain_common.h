/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 8-bit AVR ATMega 128, Fast speed code (C+ASM)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#ifndef GRAIN_COMMON
#define GRAIN_COMMON

#include <stdint.h>
#include "constants.h"


static inline uint8_t SWAP(uint8_t x)
{	return (x>>4)|(x<<4);	/* this compiles into a single AVR instruction (swap rd) */
}


uint8_t grain_getz(GrainState * g);
void grain_auth(GrainState * g, uint8_t msg);
uint8_t grain_update(GrainState * g);
void grain_encdec(uint8_t *state, uint8_t *message, uint32_t message_length, uint8_t pt_mask);

#endif

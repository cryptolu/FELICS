/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 8-bit AVR ATMega 128, Fast speed code (C+ASM)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

void ProcessCiphertext(uint8_t *state, uint8_t *message, uint32_t message_length)
{
	grain_encdec(state, message, message_length, 0x00);
}

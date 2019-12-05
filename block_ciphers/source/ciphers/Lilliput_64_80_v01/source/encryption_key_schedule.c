/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <string.h>

#include "cipher.h"
#include "constants.h"


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	
  uint8_t tmp[8];
  int8_t i, j;
  uint8_t tmpKey[20];
  memcpy(tmpKey, key, 20);
  
  /* 29 rounds */
  for(i = 0 ; i < 29 ; i++)
  {
    /* ExtractRoundKey */
    
	tmp[0] = tmpKey[1];
	tmp[1] = tmpKey[3];
	tmp[2] = tmpKey[6];
	tmp[3] = tmpKey[9];
	tmp[4] = tmpKey[10];
	tmp[5] = tmpKey[13];
	tmp[6] = tmpKey[16];
	tmp[7] = tmpKey[18];
  
    
    roundKeys[i*8 + 0] = 0;
    roundKeys[i*8 + 1] = 0;
    roundKeys[i*8 + 2] = 0;
    roundKeys[i*8 + 3] = 0;
    roundKeys[i*8 + 4] = 0;
    roundKeys[i*8 + 5] = 0;
    roundKeys[i*8 + 6] = 0;
    roundKeys[i*8 + 7] = 0;
    
    for(j = 0 ; j < 32 ; j++)
    {
      if(tmp[j>>2] & 0x01)
      {
        roundKeys[i*8 + (READ_MULT_BYTE(mul4mod31[j])>>2)] |= (uint8_t)0x01 << (READ_MULT_BYTE(mul4mod31[j]) & 0x3);
      }
      tmp[j>>2] >>= 1;
    }
	  
	  roundKeys[i*8 + 0] = READ_SBOX_BYTE(S[roundKeys[i*8 + 0]]);
	  roundKeys[i*8 + 1] = READ_SBOX_BYTE(S[roundKeys[i*8 + 1]]);
	  roundKeys[i*8 + 2] = READ_SBOX_BYTE(S[roundKeys[i*8 + 2]]);
	  roundKeys[i*8 + 3] = READ_SBOX_BYTE(S[roundKeys[i*8 + 3]]);
	  roundKeys[i*8 + 4] = READ_SBOX_BYTE(S[roundKeys[i*8 + 4]]);
	  roundKeys[i*8 + 5] = READ_SBOX_BYTE(S[roundKeys[i*8 + 5]]);
	  
	  roundKeys[i*8 + 6] = READ_SBOX_BYTE(S[roundKeys[i*8 + 6]]) ^ (i << 3) & 0x0f;
	  roundKeys[i*8 + 7] = READ_SBOX_BYTE(S[roundKeys[i*8 + 7]]) ^ (i >> 1) & 0x0f;
    
    
    /* MixingLFSM */
   
    /* 1er lfsr */
    tmpKey[0] ^= (tmpKey[4] >> 1) ^ ((tmpKey[4] << 3) & 0x0f);
    tmpKey[1] ^= tmpKey[2] >> 3;
    
    /* 2e lfsr */
    tmpKey[6] ^= (tmpKey[7] << 3) & 0x0f;
    tmpKey[9] ^= ((tmpKey[8] << 1) & 0x0f) ^ (tmpKey[8] >> 3);
    
    /* 3e lfsr */
    tmpKey[11] ^= (tmpKey[12] >> 1) ^ ((tmpKey[12] << 3) & 0x0f);
    tmpKey[13] ^= tmpKey[12] >> 3;
    
    /* 4e lfsr */
    tmpKey[16] ^= ((tmpKey[15] << 3) & 0x0f) ^ ((tmpKey[17] << 1) & 0x0f) ^ (tmpKey[17] >> 3);
    
    /* PermutationLFSM */

    
    uint8_t Temp = tmpKey[4];
    tmpKey[4] = tmpKey[3];
    tmpKey[3] = tmpKey[2];
    tmpKey[2] = tmpKey[1];
    tmpKey[1] = tmpKey[0];
    tmpKey[0] = Temp;
    
    Temp = tmpKey[9];
    tmpKey[9] = tmpKey[8];
    tmpKey[8] = tmpKey[7];
    tmpKey[7] = tmpKey[6];
    tmpKey[6] = tmpKey[5];
    tmpKey[5] = Temp;
    
    Temp = tmpKey[14];
    tmpKey[14] = tmpKey[13];
    tmpKey[13] = tmpKey[12];
    tmpKey[12] = tmpKey[11];
    tmpKey[11] = tmpKey[10];
    tmpKey[10] = Temp;
    
    Temp = tmpKey[19];
    tmpKey[19] = tmpKey[18];
    tmpKey[18] = tmpKey[17];
    tmpKey[17] = tmpKey[16];
    tmpKey[16] = tmpKey[15];
    tmpKey[15] = Temp;
    
  }
  
  /* last ExtractRoundKey */
  
  tmp[0] = tmpKey[1];
  tmp[1] = tmpKey[3];
  tmp[2] = tmpKey[6];
  tmp[3] = tmpKey[9];
  tmp[4] = tmpKey[10];
  tmp[5] = tmpKey[13];
  tmp[6] = tmpKey[16];
  tmp[7] = tmpKey[18];
  
  
  roundKeys[i*8 + 0] = 0;
  roundKeys[i*8 + 1] = 0;
  roundKeys[i*8 + 2] = 0;
  roundKeys[i*8 + 3] = 0;
  roundKeys[i*8 + 4] = 0;
  roundKeys[i*8 + 5] = 0;
  roundKeys[i*8 + 6] = 0;
  roundKeys[i*8 + 7] = 0;
  
  for(j = 0 ; j < 32 ; j++)
  {
    if(tmp[j>>2] & 0x01)
    {
      roundKeys[i*8 + (READ_MULT_BYTE(mul4mod31[j])>>2)] |= (uint8_t)0x01 << (READ_MULT_BYTE(mul4mod31[j]) & 0x3);
    }
    tmp[j>>2] >>= 1;
  }
  
	
	roundKeys[i*8 + 0] = READ_SBOX_BYTE(S[roundKeys[i*8 + 0]]);
	roundKeys[i*8 + 1] = READ_SBOX_BYTE(S[roundKeys[i*8 + 1]]);
	roundKeys[i*8 + 2] = READ_SBOX_BYTE(S[roundKeys[i*8 + 2]]);
	roundKeys[i*8 + 3] = READ_SBOX_BYTE(S[roundKeys[i*8 + 3]]);
	roundKeys[i*8 + 4] = READ_SBOX_BYTE(S[roundKeys[i*8 + 4]]);
	roundKeys[i*8 + 5] = READ_SBOX_BYTE(S[roundKeys[i*8 + 5]]);
	
	roundKeys[i*8 + 6] = READ_SBOX_BYTE(S[roundKeys[i*8 + 6]]) ^ (i << 3) & 0x0f;
	roundKeys[i*8 + 7] = READ_SBOX_BYTE(S[roundKeys[i*8 + 7]]) ^ (i >> 1) & 0x0f;
  
}

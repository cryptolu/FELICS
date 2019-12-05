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
	int8_t i;
  	
  	uint8_t tmpKey[20];
  memcpy(tmpKey, key, 20);

  /* 29 rounds */
  for(i = 0 ; i < 29 ; i++)
  {
    /* ExtractRoundKey */ 
		
		roundKeys[i*8 + 7] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[18] & 0x8)) | ((tmpKey[13] & 0x8)>>1) | ((tmpKey[9] & 0x8)>>2) | ((tmpKey[3] & 0x8)>>3) ) ) ]) ; 
		roundKeys[i*8 + 6] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[18] & 0x4)<<1) | ((tmpKey[13] & 0x4)) | ((tmpKey[9] & 0x4)>>1) | ((tmpKey[3] & 0x4)>>2) ) )]);
		
		roundKeys[i*8 + 5] = READ_SBOX_BYTE(S[((uint8_t)( ((tmpKey[18] & 0x2)<<2) | ((tmpKey[13] & 0x2)<<1) | ((tmpKey[9] & 0x2)) | ((tmpKey[3] & 0x2)>>1) ) ) ]); 
		roundKeys[i*8 + 4] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[18] & 0x1)<<3) | ((tmpKey[13] & 0x1)<<2) | ((tmpKey[9] & 0x1)<<1) | ((tmpKey[3] & 0x1)) )  ) ]);
		
		roundKeys[i*8 + 3] = READ_SBOX_BYTE(S[ ((uint8_t)( ((tmpKey[16] & 0x8)) | ((tmpKey[10] & 0x8)>>1) | ((tmpKey[6] & 0x8)>>2) | ((tmpKey[1] & 0x8)>>3) ) ) ]); 
		roundKeys[i*8 + 2] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[16] & 0x4)<<1) | ((tmpKey[10] & 0x4)) | ((tmpKey[6] & 0x4)>>1) | ((tmpKey[1] & 0x4)>>2)  ) ) ]);
		
		roundKeys[i*8 + 1] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[16] & 0x2)<<2) | ((tmpKey[10] & 0x2)<<1) | ((tmpKey[6] & 0x2)) | ((tmpKey[1] & 0x2)>>1) ) ) ]) ; 
		roundKeys[i*8 + 0] =  READ_SBOX_BYTE(S[((uint8_t)( ((tmpKey[16] & 0x1)<<3) | ((tmpKey[10] & 0x1)<<2) | ((tmpKey[6] & 0x1)<<1) | ((tmpKey[1] & 0x1)) ) )]);
		
		uint8_t tempi =  ((i<<7 & 0x80) ^ (i>>1 & 0x0f) );
    	roundKeys[i*8 + 7] ^= ( tempi & 0x0f );
    	roundKeys[i*8 + 6] ^= (( tempi & 0xf0 ) >>4);
    
    /* MixingLFSM + PermutationLFSM */
		uint8_t temp;
		/* 1er lfsr */
		temp = tmpKey[0] ;
		tmpKey[0] = tmpKey[4];
		tmpKey[4] = tmpKey[3];
		tmpKey[3] = tmpKey[2];
		tmpKey[2] = tmpKey[1] ^ (tmpKey[2]>>3);
    	tmpKey[1] = temp ^ (tmpKey[0]>>1) ^ ( (tmpKey[0]<<3) & 0x0f);
		
    
    /* 2e lfsr */
		temp = tmpKey[5];
		tmpKey[5] = tmpKey[9] ^ ( (tmpKey[8]<<1) & 0x0f) ^ (tmpKey[8]>>3);
		tmpKey[9] = tmpKey[8];
		tmpKey[8] = tmpKey[7];
		tmpKey[7] = ( (tmpKey[7]<<3) & 0x0f) ^ tmpKey[6];
		tmpKey[6] = temp;
    
    /* 3e lfsr */
		temp = tmpKey[10];
		tmpKey[10] = tmpKey[14];
		tmpKey[14] = tmpKey[13] ^ (tmpKey[12]>>3);
		tmpKey[13] = tmpKey[12];
		tmpKey[12] = (tmpKey[12]>>1) ^ ((tmpKey[12]<<3) & 0x0f) ^ tmpKey[11];
		tmpKey[11] = temp;
    
    /* 4e lfsr */
    	temp = tmpKey[15];
		tmpKey[15] = tmpKey[19];
		tmpKey[19] = tmpKey[18];
		tmpKey[18] = tmpKey[17];
		tmpKey[17] = ( ((tmpKey[17]<<1) & 0x0f) ^ (tmpKey[17]>>3) ) ^ (tmpKey[16] ^ ( (temp<<3) & 0x0f));
		tmpKey[16] = temp;
        
  }
  
  /* last ExtractRoundKey */

  /* ExtractRoundKey	 */
	roundKeys[i*8 + 7] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[18] & 0x8)) | ((tmpKey[13] & 0x8)>>1) | ((tmpKey[9] & 0x8)>>2) | ((tmpKey[3] & 0x8)>>3) ) ) ]) ; 
	roundKeys[i*8 + 6] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[18] & 0x4)<<1) | ((tmpKey[13] & 0x4)) | ((tmpKey[9] & 0x4)>>1) | ((tmpKey[3] & 0x4)>>2) ) )]);
	
	roundKeys[i*8 + 5] = READ_SBOX_BYTE(S[((uint8_t)( ((tmpKey[18] & 0x2)<<2) | ((tmpKey[13] & 0x2)<<1) | ((tmpKey[9] & 0x2)) | ((tmpKey[3] & 0x2)>>1) ) ) ]); 
	roundKeys[i*8 + 4] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[18] & 0x1)<<3) | ((tmpKey[13] & 0x1)<<2) | ((tmpKey[9] & 0x1)<<1) | ((tmpKey[3] & 0x1)) )  ) ]);
	
	roundKeys[i*8 + 3] = READ_SBOX_BYTE(S[ ((uint8_t)( ((tmpKey[16] & 0x8)) | ((tmpKey[10] & 0x8)>>1) | ((tmpKey[6] & 0x8)>>2) | ((tmpKey[1] & 0x8)>>3) ) ) ]); 
	roundKeys[i*8 + 2] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[16] & 0x4)<<1) | ((tmpKey[10] & 0x4)) | ((tmpKey[6] & 0x4)>>1) | ((tmpKey[1] & 0x4)>>2)  ) ) ]);
	
	roundKeys[i*8 + 1] = READ_SBOX_BYTE(S[( (uint8_t)( ((tmpKey[16] & 0x2)<<2) | ((tmpKey[10] & 0x2)<<1) | ((tmpKey[6] & 0x2)) | ((tmpKey[1] & 0x2)>>1) ) ) ]) ; 
	roundKeys[i*8 + 0] =  READ_SBOX_BYTE(S[((uint8_t)( ((tmpKey[16] & 0x1)<<3) | ((tmpKey[10] & 0x1)<<2) | ((tmpKey[6] & 0x1)<<1) | ((tmpKey[1] & 0x1)) ) )]);
	
	roundKeys[i*8 + 7] ^= ( ((i<<7 & 0x80) ^ (i>>1 & 0x0f) ) & 0x0f );
	roundKeys[i*8 + 6] ^= (( ((i<<7 & 0x80) ^ (i>>1 & 0x0f) ) & 0xf0 ) >>4);
}

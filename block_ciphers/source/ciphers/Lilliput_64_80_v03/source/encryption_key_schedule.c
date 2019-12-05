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

#include "cipher.h"
#include "constants.h"


struct LFSM{
	uint8_t y0:4;
	uint8_t y1:4;
	uint8_t y2:4;
	uint8_t y3:4;
	uint8_t y4:4;
	
	uint8_t y5:4;
	uint8_t y6:4;
	uint8_t y7:4;
	uint8_t y8:4;
	uint8_t y9:4;
	
	uint8_t y10:4;
	uint8_t y11:4;
	uint8_t y12:4;
	uint8_t y13:4;
	uint8_t y14:4;
	
	uint8_t y15:4;
	uint8_t y16:4;
	uint8_t y17:4;
	uint8_t y18:4;
	uint8_t y19:4;
};

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	int8_t i;
  
	struct LFSM Y;

	Y.y19 = (key[9] & 0x0f) ;
	Y.y18 = (key[9] & 0xf0) >>4;
	Y.y17 = (key[8] & 0x0f);
	Y.y16 = (key[8] & 0xf0) >>4;
	Y.y15 = (key[7] & 0x0f);
	
	Y.y14 = (key[7] & 0xf0)>>4;
	Y.y13 = (key[6] & 0x0f);
	Y.y12 = (key[6] & 0xf0) >>4;
	Y.y11 = (key[5] & 0x0f);
	Y.y10 = (key[5] & 0xf0) >>4;
	
	Y.y9 = (key[4] & 0x0f);
	Y.y8 = (key[4] & 0xf0) >>4;
	Y.y7 = (key[3] & 0x0f);
	Y.y6 = (key[3] & 0xf0) >>4;
	Y.y5 = (key[2] & 0x0f);
	
	Y.y4 = (key[2] & 0xf0) >>4;
	Y.y3 = (key[1] & 0x0f);
	Y.y2 = (key[1] & 0xf0) >>4;
	Y.y1 = (key[0] & 0x0f);
	Y.y0 = (key[0] & 0xf0) >>4;
	

  /* 29 rounds */
  for(i = 0 ; i < 29 ; i++)
  {
	  
    /* ExtractRoundKey */ 
		
		roundKeys[i*4 + 3] = READ_SBOX_BYTE(nS[( (uint8_t)( ((Y.y18 & 0x8)) | ((Y.y13 & 0x8)>>1) | ((Y.y9 & 0x8)>>2) | ((Y.y3 & 0x8)>>3) ) ) | 
		( (uint8_t)( ((Y.y18 & 0x4)<<1) | ((Y.y13 & 0x4)) | ((Y.y9 & 0x4)>>1) | ((Y.y3 & 0x4)>>2) ) <<4)]);
		
		roundKeys[i*4 + 2] = READ_SBOX_BYTE(nS[((uint8_t)( ((Y.y18 & 0x2)<<2) | ((Y.y13 & 0x2)<<1) | ((Y.y9 & 0x2)) | ((Y.y3 & 0x2)>>1) ) ) | 
		( (uint8_t)( ((Y.y18 & 0x1)<<3) | ((Y.y13 & 0x1)<<2) | ((Y.y9 & 0x1)<<1) | ((Y.y3 & 0x1)) )  <<4) ]);
		
		roundKeys[i*4 + 1] = READ_SBOX_BYTE(nS[ ((uint8_t)( ((Y.y16 & 0x8)) | ((Y.y10 & 0x8)>>1) | ((Y.y6 & 0x8)>>2) | ((Y.y1 & 0x8)>>3) ) | 
		 ( (uint8_t)( ((Y.y16 & 0x4)<<1) | ((Y.y10 & 0x4)) | ((Y.y6 & 0x4)>>1) | ((Y.y1 & 0x4)>>2) ) )<<4) ]);
		
		roundKeys[i*4 + 0] = READ_SBOX_BYTE(nS[( (uint8_t)( ((Y.y16 & 0x2)<<2) | ((Y.y10 & 0x2)<<1) | ((Y.y6 & 0x2)) | ((Y.y1 & 0x2)>>1) ) ) | 
		((uint8_t)( ((Y.y16 & 0x1)<<3) | ((Y.y10 & 0x1)<<2) | ((Y.y6 & 0x1)<<1) | ((Y.y1 & 0x1)) ) <<4)]);
		
    	roundKeys[i*4 + 3] ^= (i<<7 & 0x80) ^ (i>>1 & 0x0f);
    
    /* MixingLFSM + PermutationLFSM */
		uint8_t temp;
		/* 1er lfsr */
		temp = Y.y0 ;
		Y.y0 = Y.y4;
		Y.y4 = Y.y3;
		Y.y3 = Y.y2;
		Y.y2 = Y.y1 ^ (Y.y2>>3);
    	Y.y1 = temp ^ (Y.y0>>1) ^ ((Y.y0<<3) & 0x0f);
		
    
    /* 2e lfsr */
		temp = Y.y5;
		Y.y5 = Y.y9 ^ (Y.y8<<1) ^ ((Y.y8>>3) & 0x0f);
		Y.y9 = Y.y8;
		Y.y8 = Y.y7;
		Y.y7 = (Y.y7<<3) ^ Y.y6;
		Y.y6 = temp;
    
    /* 3e lfsr */
		temp = Y.y10;
		Y.y10 = Y.y14;
		Y.y14 = Y.y13 ^ (Y.y12>>3);
		Y.y13 = Y.y12;
		Y.y12 = (Y.y12>>1) ^ ((Y.y12<<3) & 0x0f) ^ Y.y11;
		Y.y11 = temp;
    
    /* 4e lfsr */
    	temp = Y.y15;
		Y.y15 = Y.y19;
		Y.y19 = Y.y18;
		Y.y18 = Y.y17;
		Y.y17 = ((Y.y17<<1) ^ ((Y.y17>>3) & 0x0f)) ^ (Y.y16 ^ (temp<<3));
		Y.y16 = temp;
   
        
  }
  
  /* last ExtractRoundKey */

  /* ExtractRoundKey	 */
		roundKeys[i*4 + 3] = READ_SBOX_BYTE(nS[( (uint8_t)( ((Y.y18 & 0x8)) | ((Y.y13 & 0x8)>>1) | ((Y.y9 & 0x8)>>2) | ((Y.y3 & 0x8)>>3) ) ) | 
		( (uint8_t)( ((Y.y18 & 0x4)<<1) | ((Y.y13 & 0x4)) | ((Y.y9 & 0x4)>>1) | ((Y.y3 & 0x4)>>2) ) <<4)]);
		
		roundKeys[i*4 + 2] = READ_SBOX_BYTE(nS[((uint8_t)( ((Y.y18 & 0x2)<<2) | ((Y.y13 & 0x2)<<1) | ((Y.y9 & 0x2)) | ((Y.y3 & 0x2)>>1) ) ) | 
		( (uint8_t)( ((Y.y18 & 0x1)<<3) | ((Y.y13 & 0x1)<<2) | ((Y.y9 & 0x1)<<1) | ((Y.y3 & 0x1)) )  <<4) ]);
		
		roundKeys[i*4 + 1] = READ_SBOX_BYTE(nS[ ((uint8_t)( ((Y.y16 & 0x8)) | ((Y.y10 & 0x8)>>1) | ((Y.y6 & 0x8)>>2) | ((Y.y1 & 0x8)>>3) ) | 
		 ( (uint8_t)( ((Y.y16 & 0x4)<<1) | ((Y.y10 & 0x4)) | ((Y.y6 & 0x4)>>1) | ((Y.y1 & 0x4)>>2) ) )<<4) ]);
		
		roundKeys[i*4 + 0] = READ_SBOX_BYTE(nS[( (uint8_t)( ((Y.y16 & 0x2)<<2) | ((Y.y10 & 0x2)<<1) | ((Y.y6 & 0x2)) | ((Y.y1 & 0x2)>>1) ) ) | 
		((uint8_t)( ((Y.y16 & 0x1)<<3) | ((Y.y10 & 0x1)<<2) | ((Y.y6 & 0x1)<<1) | ((Y.y1 & 0x1)) ) <<4)]);
		
    roundKeys[i*4 + 3] ^= (i<<7 & 0x80) ^ (i>>1 & 0x0f);
}

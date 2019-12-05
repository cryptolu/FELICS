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

/* use relatively small table to be compatible with AVR ROM size */
#ifdef AVR

#define rot4(x) ((uint8_t) (x<<4)| (x>>4)) 

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
  uint8_t i=0;
	
  /*29 rounds */
  for(i = 0 ; i < 29 ; i++)
  {
    /* NonLinearLayer + LinearLayer */
		uint8_t tmpx7 = block[3]&0x0f;
		uint8_t tmpx7x7 = tmpx7 | (tmpx7<<4);
		block[7] = READ_SBOX_BYTE(nSinv[block[0] ^ rot4(READ_ROUND_KEY_BYTE(roundKeys[i*4 + 3]) )]) ^tmpx7x7 ^ block[7] ^ (block[3]>>4) ^ (block[2]&0x0f) ^ (block[2]>>4) ^ (block[1]&0x0f) ^ (block[1]>>4) ^ (block[0]&0x0f);
		block[6] = READ_SBOX_BYTE(nSinv[block[1] ^ rot4(READ_ROUND_KEY_BYTE(roundKeys[i*4 + 2]) )]) ^tmpx7x7 ^ block[6];
		block[5] = READ_SBOX_BYTE(nSinv[block[2] ^ rot4(READ_ROUND_KEY_BYTE(roundKeys[i*4 + 1]) )]) ^tmpx7x7 ^ block[5];
		block[4] = READ_SBOX_BYTE(nSinv[block[3] ^ rot4(READ_ROUND_KEY_BYTE(roundKeys[i*4 + 0]) )]) ^ tmpx7 ^ block[4];
    
    
    /* PermutationLayer */

    /* Avoid useless operation in the for loops and create as many temp as necessary, use all the temp at the end */
		uint8_t temp4 = block[4];
		block[4] = (block[0]&0x0f ) | (block[1]<<4);
		uint8_t temp5 = block[5];
		block[5] = block[2];
		uint8_t temp6 = block[6];
		block[6] = (block[0]>>4) | (block[3]&0xf0) ;
		uint8_t temp7 = block[7];
		block[7] = (block[1]&0xf0) | (block[3]&0x0f);
		
		block[0] = (temp7&0xf0) | (temp5&0x0f);
		block[1] = (temp6&0xf0) | (temp5>>4);
		block[2] = temp4;
		block[3] = (temp7&0x0f) | (temp6<<4);

  } /* end round  */
	
  /* last round */
	uint8_t tmpx7 = block[3]&0x0f;
	
	uint8_t tmpx7x7 = tmpx7 | (tmpx7<<4);
	block[7] = READ_SBOX_BYTE(nSinv[block[0] ^ rot4(READ_ROUND_KEY_BYTE(roundKeys[i*4 + 3]) )]) ^tmpx7x7 ^ block[7] ^ (block[3]>>4) ^ (block[2]&0x0f) ^ (block[2]>>4) ^ (block[1]&0x0f) ^ (block[1]>>4) ^ (block[0]&0x0f);
	block[6] = READ_SBOX_BYTE(nSinv[block[1] ^ rot4(READ_ROUND_KEY_BYTE(roundKeys[i*4 + 2]) )]) ^tmpx7x7 ^ block[6];
	block[5] = READ_SBOX_BYTE(nSinv[block[2] ^ rot4(READ_ROUND_KEY_BYTE(roundKeys[i*4 + 1]) )]) ^tmpx7x7 ^ block[5];
	block[4] = READ_SBOX_BYTE(nSinv[block[3] ^ rot4(READ_ROUND_KEY_BYTE(roundKeys[i*4 + 0]) )]) ^ tmpx7 ^ block[4];
		
}


/* can use larger table since ROM resources are larger */
#else

#define rot4(x) ((uint8_t) (x<<4)| (x>>4)) 

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
  uint8_t i=0;
	
  /*29 rounds */
  for(i = 0 ; i < 29 ; i++)
  {
    /* NonLinearLayer + LinearLayer */
		uint8_t tmpx7 = block[3]&0x0f;
		block[7] = READ_SBOX_BYTE(nSinvx7x7[block[0] ^ rot4(READ_ROUND_KEY_BYTE(roundKeys[i*4 + 3]))][tmpx7]) ^ block[7] ^ (block[3]>>4) ^ (block[2]&0x0f) ^ (block[2]>>4) ^ (block[1]&0x0f) ^ (block[1]>>4) ^ (block[0]&0x0f);
		block[6] = READ_SBOX_BYTE(nSinvx7x7[block[1] ^ rot4(READ_ROUND_KEY_BYTE(roundKeys[i*4 + 2]))][tmpx7]) ^ block[6];
		block[5] = READ_SBOX_BYTE(nSinvx7x7[block[2] ^ rot4(READ_ROUND_KEY_BYTE(roundKeys[i*4 + 1]))][tmpx7]) ^ block[5];
		block[4] = READ_SBOX_BYTE(nSinv[block[3] ^ rot4(READ_ROUND_KEY_BYTE(roundKeys[i*4 + 0]) ) ]) ^ tmpx7 ^ block[4];
    
     
    /* PermutationLayer */

    /*Avoid useless operation in the for loops and create as many temp as necessary, use all the temp at the end */
		uint8_t temp4 = block[4];
		block[4] = (block[0]&0x0f ) | (block[1]<<4);
		uint8_t temp5 = block[5];
		block[5] = block[2];
		uint8_t temp6 = block[6];
		block[6] = (block[0]>>4) | (block[3]&0xf0) ;
		uint8_t temp7 = block[7];
		block[7] = (block[1]&0xf0) | (block[3]&0x0f);
		
		block[0] = (temp7&0xf0) | (temp5&0x0f);
		block[1] = (temp6&0xf0) | (temp5>>4);
		block[2] = temp4;
		block[3] = (temp7&0x0f) | (temp6<<4);

  } /* end round */
	
  /* last round */
	uint8_t tmpx7 = block[3]&0x0f;
	block[7] = READ_SBOX_BYTE(nSinvx7x7[block[0] ^ rot4(READ_ROUND_KEY_BYTE(roundKeys[i*4 + 3]))][tmpx7]) ^ block[7] ^ (block[3]>>4) ^ (block[2]&0x0f) ^ (block[2]>>4) ^ (block[1]&0x0f) ^ (block[1]>>4) ^ (block[0]&0x0f);
	block[6] = READ_SBOX_BYTE(nSinvx7x7[block[1] ^ rot4(READ_ROUND_KEY_BYTE(roundKeys[i*4 + 2]))][tmpx7]) ^ block[6];
	block[5] = READ_SBOX_BYTE(nSinvx7x7[block[2] ^ rot4(READ_ROUND_KEY_BYTE(roundKeys[i*4 + 1]))][tmpx7]) ^ block[5];
	block[4] = READ_SBOX_BYTE(nSinv[block[3] ^ rot4( READ_ROUND_KEY_BYTE(roundKeys[i*4 + 0]) ) ]) ^ tmpx7 ^ block[4];
}

#endif


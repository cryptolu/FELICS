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


void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	
  uint8_t i;
  uint8_t tmpblock[16];
  memcpy(tmpblock, block, 16);
  
  /*29 rounds */
  for(i = 0 ; i < 29 ; i++)
  {
    uint8_t tmproundKeysi[8];

  	memcpy(tmproundKeysi, roundKeys + i*8, 8);
    
    /* NonLinearLayer + LinearLayer */
    
    tmpblock[8]  ^= (READ_SBOX_BYTE( S[tmpblock[7] ^ READ_ROUND_KEY_BYTE(tmproundKeysi[ 0])])) ;
    tmpblock[9]  ^= (READ_SBOX_BYTE( S[tmpblock[6] ^ READ_ROUND_KEY_BYTE(tmproundKeysi[ 1])]) ^ tmpblock[7]);
    tmpblock[10] ^= (READ_SBOX_BYTE (S[tmpblock[5] ^ READ_ROUND_KEY_BYTE(tmproundKeysi[ 2])]) ^ tmpblock[7]);
    tmpblock[11] ^= (READ_SBOX_BYTE (S[tmpblock[4] ^ READ_ROUND_KEY_BYTE(tmproundKeysi[ 3])]) ^ tmpblock[7]);
    tmpblock[12] ^= (READ_SBOX_BYTE( S[tmpblock[3] ^ READ_ROUND_KEY_BYTE(tmproundKeysi[ 4])]) ^ tmpblock[7]);
    tmpblock[13] ^= (READ_SBOX_BYTE( S[tmpblock[2] ^ READ_ROUND_KEY_BYTE(tmproundKeysi[ 5])]) ^ tmpblock[7]);
    tmpblock[14] ^= (READ_SBOX_BYTE( S[tmpblock[1] ^ READ_ROUND_KEY_BYTE(tmproundKeysi[ 6])]) ^ tmpblock[7]);
    tmpblock[15] ^= (READ_SBOX_BYTE( S[tmpblock[0] ^ READ_ROUND_KEY_BYTE(tmproundKeysi[ 7])]) ^ tmpblock[7] ^ tmpblock[6] ^ tmpblock[5] ^ tmpblock[4] ^ tmpblock[3] ^ tmpblock[2] ^ tmpblock[1]);
    
    
    /* PermutationLayer */

    /*Avoid useless operation in the for loops and create as many temp as necessary, use all the temp at the end */
    uint8_t temp13 = tmpblock[13];
	tmpblock[13] = tmpblock[0];
	uint8_t temp9 = tmpblock[9];
	tmpblock[9] = tmpblock[1];
	uint8_t temp14 = tmpblock[14];
	tmpblock[14] = tmpblock[2];
	uint8_t temp8 = tmpblock[8];
	tmpblock[8] = tmpblock[3];
	uint8_t temp10 = tmpblock[10];
	tmpblock[10] = tmpblock[4];
	uint8_t temp11 = tmpblock[11];
	tmpblock[11] = tmpblock[5];
	uint8_t temp12 = tmpblock[12];
	tmpblock[12] = tmpblock[6];
	uint8_t temp15 = tmpblock[15];
	tmpblock[15] = tmpblock[7];
	
	tmpblock[4] = temp8;
	tmpblock[5] = temp9;
	tmpblock[3] = temp10;
	tmpblock[1] = temp11;
	tmpblock[2] = temp12;
	tmpblock[6] = temp13;
	tmpblock[0] = temp14;
	tmpblock[7] = temp15;
	
  } /* end round */
  
  uint8_t tmproundKeysi[8];
  memcpy(tmproundKeysi, roundKeys + i*8, 8);
  
  /* last round */
    

  tmpblock[8]  ^= (READ_SBOX_BYTE( S[tmpblock[7] ^ READ_ROUND_KEY_BYTE(tmproundKeysi[ 0])]));
  tmpblock[9]  ^= (READ_SBOX_BYTE( S[tmpblock[6] ^ READ_ROUND_KEY_BYTE(tmproundKeysi[ 1])]) ^ tmpblock[7]);
  tmpblock[10] ^= (READ_SBOX_BYTE( S[tmpblock[5] ^ READ_ROUND_KEY_BYTE(tmproundKeysi[ 2])]) ^ tmpblock[7]);
  tmpblock[11] ^= (READ_SBOX_BYTE( S[tmpblock[4] ^ READ_ROUND_KEY_BYTE(tmproundKeysi[ 3])]) ^ tmpblock[7]);
  tmpblock[12] ^= (READ_SBOX_BYTE( S[tmpblock[3] ^ READ_ROUND_KEY_BYTE(tmproundKeysi[ 4])]) ^ tmpblock[7]);
  tmpblock[13] ^= (READ_SBOX_BYTE( S[tmpblock[2] ^ READ_ROUND_KEY_BYTE(tmproundKeysi[ 5])]) ^ tmpblock[7]);
  tmpblock[14] ^= (READ_SBOX_BYTE( S[tmpblock[1] ^ READ_ROUND_KEY_BYTE(tmproundKeysi[ 6])]) ^ tmpblock[7]);
  tmpblock[15] ^= (READ_SBOX_BYTE( S[tmpblock[0] ^ READ_ROUND_KEY_BYTE(tmproundKeysi[ 7])]) ^ tmpblock[7] ^ tmpblock[6] ^ tmpblock[5] ^ tmpblock[4] ^ tmpblock[3] ^ tmpblock[2] ^ tmpblock[1]);
  
  memcpy(block, tmpblock, 16);
	
}

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


void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	
	uint8_t i;

  
  /*29 rounds */
  for(i = 0 ; i < 29 ; i++)
  {

    
    /* NonLinearLayer + LinearLayer */
    
    block[8]  ^= (READ_SBOX_BYTE( S[block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 0])])) ;
    block[9]  ^= (READ_SBOX_BYTE( S[block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 1])]) ^ block[7]);
    block[10] ^= (READ_SBOX_BYTE (S[block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 2])]) ^ block[7]);
    block[11] ^= (READ_SBOX_BYTE (S[block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 3])]) ^ block[7]);
    block[12] ^= (READ_SBOX_BYTE( S[block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 4])]) ^ block[7]);
    block[13] ^= (READ_SBOX_BYTE( S[block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 5])]) ^ block[7]);
    block[14] ^= (READ_SBOX_BYTE( S[block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 6])]) ^ block[7]);
    block[15] ^= (READ_SBOX_BYTE( S[block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 7])]) ^ block[7] ^ block[6] ^ block[5] ^ block[4] ^ block[3] ^ block[2] ^ block[1]);
    
    
    /* PermutationLayer */
	uint8_t j; 
	uint8_t tmp[16];
	for(j = 0 ; j < 16 ; j++)
	tmp[ READ_SBOX_BYTE(P[j]) ] = block[j];

	for(j = 0 ; j < 16 ; j++)
	block[j] = tmp[j];
	
  } /* end round  */

  
  /* last round */
    

  block[8]  ^= (READ_SBOX_BYTE( S[block[7] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 0])]));
  block[9]  ^= (READ_SBOX_BYTE( S[block[6] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 1])]) ^ block[7]);
  block[10] ^= (READ_SBOX_BYTE( S[block[5] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 2])]) ^ block[7]);
  block[11] ^= (READ_SBOX_BYTE( S[block[4] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 3])]) ^ block[7]);
  block[12] ^= (READ_SBOX_BYTE( S[block[3] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 4])]) ^ block[7]);
  block[13] ^= (READ_SBOX_BYTE( S[block[2] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 5])]) ^ block[7]);
  block[14] ^= (READ_SBOX_BYTE( S[block[1] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 6])]) ^ block[7]);
  block[15] ^= (READ_SBOX_BYTE( S[block[0] ^ READ_ROUND_KEY_BYTE(roundKeys[i*8 + 7])]) ^ block[7] ^ block[6] ^ block[5] ^ block[4] ^ block[3] ^ block[2] ^ block[1]);
  
	
}

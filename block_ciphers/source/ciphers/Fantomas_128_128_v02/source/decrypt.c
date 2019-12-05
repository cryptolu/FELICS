/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Johann Großschädl <johann.groszschaedl@uni.lu>
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

#include "sbox_inv.h"


void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	/*
	 *
	 * Access state as 16-bit values
	 * Assumes little-endian machine
	 *
	 */
	uint16_t *data = (uint16_t *)block;
	uint16_t *key = (uint16_t *)roundKeys;
	uint8_t i, j;

	
	/* Initial key addition */
	for (j = 0; j < 8; j++)
	{
		data[j] ^= READ_ROUND_KEY_WORD(key[j]);
	}

	for (i = 0; i < NUMBER_OF_ROUNDS; i++)
	{
		/* LBox layer (tables) */
		for (j = 0; j < 8; j++)
		{
			data[j] = READ_LBOX_INV_WORD(LBoxInv2[data[j] >> 8]) ^ 
						READ_LBOX_INV_WORD(LBoxInv1[data[j] & 0xff]);
		}

		/* SBox layer (bitsliced) */
		SBOX_Inv(data);

		/* Key addition */
		for (j = 0; j < 8; j++)
		{
			data[j] ^= READ_ROUND_KEY_WORD(key[j]);
		}

		/* Round constant */
		data[0] ^= READ_LBOX_WORD(LBox1[12 - i]);
	}
}

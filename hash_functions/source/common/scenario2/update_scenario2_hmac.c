/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2017 University of Luxembourg
 *
 * Written in 2017 by Virat Shejwalkar <virat.shejwalkar@uni.lu>
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

#include "scenario2.h"
#include "cipher.h"
#include "common.h"

void UpdateScenario2HMAC(uint8_t *message, uint8_t *digest)
{
	RAM_DATA_BYTE internal_key[BLOCK_SIZE] = {0};
	RAM_DATA_BYTE k_pad[BLOCK_SIZE];
	RAM_DATA_BYTE state[STATE_SIZE];
	uint8_t i;

	/* Generate internal key */
	if (KEY_SIZE > BLOCK_SIZE)
	{
		Initialize(state);
		Update(state, MAC_KEY, KEY_SIZE);
		Finalize(state, internal_key);
	}
	else
	{
		for (i = 0; i < KEY_SIZE; i++)
		{
			internal_key[i] = MAC_KEY[i];
		}
	}
	/* inner padding */
	for (i = 0; i < BLOCK_SIZE; i++)
	{
		k_pad[i] = internal_key[i] ^ 0x36;
	}
	/* 1st hash */
	Initialize(state);
	Update(state, k_pad, BLOCK_SIZE);
	Update(state, message, MESSAGE_SIZE);
	Finalize(state, digest);
	/* outer padding */
	for (i = 0; i < BLOCK_SIZE; i++)
	{
		k_pad[i] = internal_key[i] ^ 0x5c;
	}
	/* 2nd hash */
	Initialize(state);
	Update(state, k_pad, BLOCK_SIZE);
	Update(state, digest, DIGEST_SIZE);
	Finalize(state, digest);
}

/* For HMAC with SHA256, the digest should be:
 0x13 0xac 0x84 0x51 0x99 0x30 0xd6 0x2d 0x56 0x24 0xf4 0xea 0x15 0x6b 0x2f 0xb5
 0x12 0xef 0xa9 0x42 0x15 0xec 0xcf 0x94 0x21 0xc9 0x25 0x9b 0x1e 0x4e 0x75 0x28
*/

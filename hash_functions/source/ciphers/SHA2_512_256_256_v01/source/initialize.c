/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2017 University of Luxembourg
 *
 * Written in 2017 by Yann Le Corre <yann.lecorre@uni.lu>
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
#include "data_types.h"
#include "constants.h"

void Initialize(uint8_t *state)
{
	sha256_state_t *sha256_state;

	sha256_state = (sha256_state_t *)state;
	sha256_state->tag_state[0] = 0x6a09e667;
	sha256_state->tag_state[1] = 0xbb67ae85;
	sha256_state->tag_state[2] = 0x3c6ef372;
	sha256_state->tag_state[3] = 0xa54ff53a;
	sha256_state->tag_state[4] = 0x510e527f;
	sha256_state->tag_state[5] = 0x9b05688c;
	sha256_state->tag_state[6] = 0x1f83d9ab;
	sha256_state->tag_state[7] = 0x5be0cd19;
	sha256_state->chunk_idx = 0;
	sha256_state->n_bytes = 0;
}

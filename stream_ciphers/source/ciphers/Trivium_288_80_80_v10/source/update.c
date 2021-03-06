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

#include "update.h"


void Update(uint8_t *state, uint8_t *t1, uint8_t *t2, uint8_t *t3, uint8_t *stream)
{
	uint8_t x1, x2, x3, x4, x5;
	

	x1 = (state[7] << 2) ^ (state[8] >> 6);
	x4 = (state[10] << 5) ^ (state[11] >> 3);

	*t1 = x1 ^ x4;


	x1 = (state[19] << 5) ^ (state[20] >> 3);
	x4 = (state[21] << 4) ^ (state[22] >> 4);

	*t2 = x1 ^ x4;


	x1 = (state[30] << 2) ^ (state[31] >> 6);
	x4 = (state[35] << 7) ^ (state[36] >> 1);
	
	*t3 = x1 ^ x4;

	
	*stream ^= *t1 ^ *t2 ^ *t3;


	x2 = (state[10] << 3) ^ (state[11] >> 5);
	x3 = (state[10] << 4) ^ (state[11] >> 4);
	x5 = (state[20] << 6) ^ (state[21] >> 2);

	*t1 ^= (x2 & x3) ^ x5;


	x2 = (state[21] << 2) ^ (state[22] >> 6);
	x3 = (state[21] << 3) ^ (state[22] >> 5);
	x5 = (state[32] << 7) ^ (state[33] >> 1);

	*t2 ^= (x2 & x3) ^ x5;


	x2 = (state[35] << 5) ^ (state[36] >> 3);
	x3 = (state[35] << 6) ^ (state[36] >> 2);
	x5 = (state[7] << 5) ^ (state[8] >> 3);
	
	*t3 ^= (x2 & x3) ^ x5;
}

/*
 *
 * National Security Research Institute
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 National Security Research Institute
 *
 * Written in 2015 by Ilwoong Jeong <iw98jeong@nsr.re.kr>
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
#include "primitives.h"

#define RK(x, y) READ_ROUND_KEY_DOUBLE_WORD(x[y])

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t* blk = (uint32_t*) block;
	uint32_t* rk = (uint32_t*) roundKeys;
	int8_t i;
	
	uint32_t b0 = blk[0];
	uint32_t b1 = blk[1];
	uint32_t b2 = blk[2];
	uint32_t b3 = blk[3];
	
	for (i = 0; i < NUMBER_OF_ROUNDS; i += 4, rk += 4) {
		b3 = rotr((b2 ^ RK(rk, 3)) + (b3 ^ RK(rk, 1)), 3);
		b2 = rotr((b1 ^ RK(rk, 2)) + (b2 ^ RK(rk, 1)), 5);
		b1 = rotl((b0 ^ RK(rk, 0)) + (b1 ^ RK(rk, 1)), 9);
		
		rk += 4;
		b0 = rotr((b3 ^ RK(rk, 3)) + (b0 ^ RK(rk, 1)), 3);
		b3 = rotr((b2 ^ RK(rk, 2)) + (b3 ^ RK(rk, 1)), 5);
		b2 = rotl((b1 ^ RK(rk, 0)) + (b2 ^ RK(rk, 1)), 9);
		
		rk += 4;
		b1 = rotr((b0 ^ RK(rk, 3)) + (b1 ^ RK(rk, 1)), 3);
		b0 = rotr((b3 ^ RK(rk, 2)) + (b0 ^ RK(rk, 1)), 5);
		b3 = rotl((b2 ^ RK(rk, 0)) + (b3 ^ RK(rk, 1)), 9);
		
		rk += 4;
		b2 = rotr((b1 ^ RK(rk, 3)) + (b2 ^ RK(rk, 1)), 3);
		b1 = rotr((b0 ^ RK(rk, 2)) + (b1 ^ RK(rk, 1)), 5);
		b0 = rotl((b3 ^ RK(rk, 0)) + (b0 ^ RK(rk, 1)), 9);
	}
	
	blk[0] = b0;
	blk[1] = b1;
	blk[2] = b2;
	blk[3] = b3;
}

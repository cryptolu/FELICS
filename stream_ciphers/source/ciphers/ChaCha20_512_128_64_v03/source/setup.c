/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2016 University of Luxembourg
 *
 * Written in 2016 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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


void Setup(uint8_t *state, uint8_t *key, uint8_t *iv)
{
	uint32_t *State = (uint32_t *)state;
	uint32_t *Key = (uint32_t *)key;
	uint32_t *IV = (uint32_t *)iv;

	
	/* First row: TAU */
	State[0] = READ_CONSTANT_DOUBLE_WORD(TAU[0]);
	State[1] = READ_CONSTANT_DOUBLE_WORD(TAU[1]);
	State[2] = READ_CONSTANT_DOUBLE_WORD(TAU[2]);
	State[3] = READ_CONSTANT_DOUBLE_WORD(TAU[3]);

	/* Second row: key */
	State[4] = Key[0];
	State[5] = Key[1];
	State[6] = Key[2];
	State[7] = Key[3];

	/* Third row: key */
	State[8] = Key[0];
	State[9] = Key[1];
	State[10] = Key[2];
	State[11] = Key[3];

	/* Forth row: IV */
	State[12] = 0;
	State[13] = 0;
	State[14] = IV[0];
	State[15] = IV[1];
}

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

#include "cipher.h"
#include "constants.h"
#include "permute.h"

void Initialize(uint8_t *state, const uint8_t *key, const uint8_t *nonce) {
    uint8_t i;
    // initialization
    state[0] = (uint8_t)KEY_SIZE *8;
    state[1] = (uint8_t)BLOCK_SIZE *8;
    state[2] = (uint8_t)pA;
    state[3] = (uint8_t)pB;

    for (i = 4; i < STATE_SIZE - 2 * KEY_SIZE; ++i) {
        state[i] = 0;
    }

    for (i = 0; i < KEY_SIZE; ++i) {
        state[STATE_SIZE - 2 * KEY_SIZE + i] = key[i];
        state[STATE_SIZE - KEY_SIZE + i] = nonce[i];
    }

    permutation(state, pA);

    for (i = 0; i < KEY_SIZE; ++i) {
        state[STATE_SIZE - KEY_SIZE + i] ^= key[i];
    }

}

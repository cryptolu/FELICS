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
#include <stdio.h>
#include "cipher.h"
#include "constants.h"
#include "permute.h"

void Initialize(uint8_t *state, const uint8_t *key, const uint8_t *nonce) {

    uint32_t *state_32 = (uint32_t *)state;
    uint32_t *key_32 = (uint32_t *)key;
    uint32_t *nonce_32 = (uint32_t *)nonce;

    uint8_t i;

    for (i = 0; i < 16; ++i) {
        state_32[i] = i;
    }

    F(state_32);
    F(state_32);

    state_32[0] = nonce_32[0];
    state_32[1] = nonce_32[1];
    state_32[2] = nonce_32[2];
    state_32[3] = nonce_32[3];

    state_32[4] = key_32[0];
    state_32[5] = key_32[1];
    state_32[6] = key_32[2];
    state_32[7] = key_32[3];

    state_32[12] ^= NORX_W;
    state_32[13] ^= NORX_L;
    state_32[14] ^= NORX_P;
    state_32[15] ^= 8 * TAG_SIZE;

    norx_permute(state_32);

    state_32[12] ^= key_32[0];
    state_32[13] ^= key_32[1];
    state_32[14] ^= key_32[2];
    state_32[15] ^= key_32[3];

}

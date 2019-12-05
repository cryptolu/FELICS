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
#include <string.h>

#include "cipher.h"
#include "constants.h"
#include "permute.h"
#include "absorption.h"
#include "norx_util.h"

void Finalize(uint8_t *state, uint8_t *key) {
    /* Add code for finalization here */

    norx_state_t state_initialize;
    norx_word_t *S = state_initialize->S;

    uint8_t i;

    /* Shift data from input state to state_initialize */
    for (i = 0; i < 16; ++i) {
        S[i] = ((uint32_t)state[4 * i + 3] << 24) | ((uint32_t)state[4 * i +
                        2] << 16) | ((uint32_t)state[4 * i +
                        1] << 8) | ((uint32_t)state[4 * i] << 0);
    }

    S[15] ^= FINAL_TAG;

    norx_permute(state_initialize);

    S[12] ^= LOAD(key + 0 * BYTES(NORX_W));
    S[13] ^= LOAD(key + 1 * BYTES(NORX_W));
    S[14] ^= LOAD(key + 2 * BYTES(NORX_W));
    S[15] ^= LOAD(key + 3 * BYTES(NORX_W));

    norx_permute(state_initialize);

    S[12] ^= LOAD(key + 0 * BYTES(NORX_W));
    S[13] ^= LOAD(key + 1 * BYTES(NORX_W));
    S[14] ^= LOAD(key + 2 * BYTES(NORX_W));
    S[15] ^= LOAD(key + 3 * BYTES(NORX_W));

    /* Shift data from state_initialize to state */
    for (i = 0; i < 16; ++i) {
        state[4 * i] = (uint8_t)(state_initialize->S[i] >> 0);
        state[4 * i + 1] = (uint8_t)(state_initialize->S[i] >> 8);
        state[4 * i + 2] = (uint8_t)(state_initialize->S[i] >> 16);
        state[4 * i + 3] = (uint8_t)(state_initialize->S[i] >> 24);
    }
}

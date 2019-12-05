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

void norx_absorb_block(uint32_t *state, const uint8_t *in, uint8_t tag) {
    uint8_t i;
    uint32_t *in_32 = (uint32_t *)in;

    state[15] ^= tag;
    norx_permute(state);

    for (i = 0; i < 12; ++i) {
        state[i] ^= in_32[i];
    }
}

void norx_absorb_lastblock(uint32_t *state, const uint8_t *in, size_t inlen,
        uint8_t tag) {
    uint8_t lastblock[BLOCK_SIZE] = { 0 };

    /* Padding part */
    memcpy(lastblock, in, inlen);
    lastblock[inlen] = 0x01;
    lastblock[BLOCK_SIZE - 1] |= 0x80;

    norx_absorb_block(state, lastblock, tag);
}

void ProcessAssociatedData(uint8_t *state, uint8_t *associatedData,
        uint32_t associated_data_length) {
    uint32_t *state_32 = (uint32_t *)state;

    if (associated_data_length > 0) {
        while (associated_data_length >= BLOCK_SIZE) {
            norx_absorb_block(state_32, associatedData, 0x01);
            associated_data_length -= BLOCK_SIZE;
            associatedData += BLOCK_SIZE;
        }
        norx_absorb_lastblock(state_32, associatedData, associated_data_length,
                0x01);
    }
}

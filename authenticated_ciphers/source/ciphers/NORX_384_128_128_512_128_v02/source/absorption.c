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

#include "permute.h"
#include "absorption.h"
#include "padding.h"

void norx_absorb_block(norx_state_t state, const uint8_t *in, tag_t tag) {
    size_t i;
    norx_word_t *S = state->S;

    S[15] ^= tag;
    norx_permute(state);

    for (i = 0; i < 12; ++i) {
        S[i] ^= LOAD(in + i * 4);
    }
}

void norx_absorb_lastblock(norx_state_t state, const uint8_t *in, size_t inlen,
        tag_t tag) {
    uint8_t lastblock[BLOCK_SIZE] = { 0 };
    norx_pad(lastblock, in, inlen);
    norx_absorb_block(state, lastblock, tag);
}

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

#include "data_types.h"
#include "constants.h"


/** \brief rotate right by <n> positions
    \param[in] a: word to be rotated
    \param[n]  n: number of positions
    \return rotated <a>
 **/
uint32_t ror(uint32_t a, uint8_t n)
{
    uint32_t x;
    uint32_t y;

    x = a >> n;
    y = a << (32 - n);
    return (x | y);
}

/** \brief round function
    \param[in] round_idx: round index
    \param[in] w shift register extension
    \param[in, out] tag_state: digest state
 **/
void rnd(uint8_t round_idx, uint32_t *w, uint32_t *tag_state)
{
    uint32_t s0;
    uint32_t s1;
    uint32_t temp1;
    uint32_t temp2;
    uint32_t ch;
    uint32_t maj;

    s1 = ror(tag_state[4], 6) ^ ror(tag_state[4], 11) ^ ror(tag_state[4], 25);
    ch = (tag_state[4] & tag_state[5]) ^ (~tag_state[4] & tag_state[6]);
    temp1 = tag_state[7] + s1 + ch + K[round_idx] + w[round_idx];
    s0 = ror(tag_state[0], 2) ^ ror(tag_state[0], 13) ^ ror(tag_state[0], 22);
    maj = (tag_state[0] & tag_state[1]) ^ (tag_state[0] & tag_state[2]) ^ (tag_state[1] & tag_state[2]);
    temp2 = s0 + maj;
    tag_state[7] = tag_state[6];
    tag_state[6] = tag_state[5];
    tag_state[5] = tag_state[4];
    tag_state[4] = tag_state[3] + temp1;
    tag_state[3] = tag_state[2];
    tag_state[2] = tag_state[1];
    tag_state[1] = tag_state[0];
    tag_state[0] = temp1 + temp2;
}


/** \brief compress one chunk. Operates ONLY on FULL chunks (i.e. 16 bytes)
    stored into sha256_state->chunk.
    \param[in, out] sha256_state: function state
 **/
void process_chunk(sha256_state_t *sha256_state)
{
    uint32_t w[64];
    uint32_t s0;
    uint32_t s1;
    uint8_t i;
    uint32_t tag_state[8];
    uint8_t *current;

    tag_state[0] = sha256_state->tag_state[0];
    tag_state[1] = sha256_state->tag_state[1];
    tag_state[2] = sha256_state->tag_state[2];
    tag_state[3] = sha256_state->tag_state[3];
    tag_state[4] = sha256_state->tag_state[4];
    tag_state[5] = sha256_state->tag_state[5];
    tag_state[6] = sha256_state->tag_state[6];
    tag_state[7] = sha256_state->tag_state[7];
    current = sha256_state->chunk;
    for (i = 0; i < 16; i++)
    {
        /* bytes to big-endian uint32_t */
        w[i] = ((uint32_t)current[0] << 24) | ((uint32_t)current[1] << 16) | ((uint32_t)current[2] << 8) | (uint32_t)current[3];
        current += 4;
        rnd(i, w, tag_state);
    }

    for (i = 16; i < 64; i++)
    {
        s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        rnd(i, w, tag_state);
    }

    sha256_state->tag_state[0] = sha256_state->tag_state[0] + tag_state[0];
    sha256_state->tag_state[1] = sha256_state->tag_state[1] + tag_state[1];
    sha256_state->tag_state[2] = sha256_state->tag_state[2] + tag_state[2];
    sha256_state->tag_state[3] = sha256_state->tag_state[3] + tag_state[3];
    sha256_state->tag_state[4] = sha256_state->tag_state[4] + tag_state[4];
    sha256_state->tag_state[5] = sha256_state->tag_state[5] + tag_state[5];
    sha256_state->tag_state[6] = sha256_state->tag_state[6] + tag_state[6];
    sha256_state->tag_state[7] = sha256_state->tag_state[7] + tag_state[7];
    sha256_state->chunk_idx = 0;
}

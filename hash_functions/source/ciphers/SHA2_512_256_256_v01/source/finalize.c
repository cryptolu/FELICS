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
#include "constants.h"
#include "process_chunk.h"

void Finalize(uint8_t *state, uint8_t *digest)
{
    sha256_state_t *sha256_state;
    uint32_t n_bits;
    uint8_t i;
    uint8_t *tag_state_ptr;

    sha256_state = (sha256_state_t *)state;
    /* the current chunk can not be full since it would have been processed in the
       previous call to update(). So we always have room for at least the 0x80 marker
     */
    sha256_state->chunk[sha256_state->chunk_idx] = 0x80;
    sha256_state->chunk_idx++;

    if (sha256_state->chunk_idx < 60)
    {
        /* pad with zeros until 4 bytes are left */
        while (sha256_state->chunk_idx < 60)
        {
            sha256_state->chunk[sha256_state->chunk_idx] = 0x00;
            sha256_state->chunk_idx++;
        }
        /* insert number of bits coded on big-endian 32-bit integer */
        n_bits = ((uint32_t)sha256_state->n_bytes << 3);
        sha256_state->chunk[60] = (n_bits >> 24) & 0xff;
        sha256_state->chunk[61] = (n_bits >> 16) & 0xff;
        sha256_state->chunk[62] = (n_bits >>  8) & 0xff;
        sha256_state->chunk[63] = (n_bits >>  0) & 0xff;
        /* process chunk */
        process_chunk(sha256_state);
    }
    else
    {
        /* fill current chunk with zeros */
        while (sha256_state->chunk_idx < 64)
        {
            sha256_state->chunk[sha256_state->chunk_idx] = 0x00;
            sha256_state->chunk_idx++;
        }
        /* process chunk */
        process_chunk(sha256_state);
        /* fill new chunk with zeros and number of bits coded on big-endian 32-bit integer */
        for (i = 0; i < 60; i++)
        {
            sha256_state->chunk[i] = 0x00;
        }
        n_bits = ((uint32_t)sha256_state->n_bytes << 3);
        sha256_state->chunk[60] = (n_bits >> 24) & 0xff;
        sha256_state->chunk[61] = (n_bits >> 16) & 0xff;
        sha256_state->chunk[62] = (n_bits >>  8) & 0xff;
        sha256_state->chunk[63] = (n_bits >>  0) & 0xff;
        /* process chunk */
        process_chunk(sha256_state);
    }
    /* get digest (which is currently state in BE) */
    tag_state_ptr = (uint8_t *)sha256_state->tag_state;
    for (i = 0; i < 8; i++)
    {
        digest[4*i + 0] = tag_state_ptr[4*i + 3];
        digest[4*i + 1] = tag_state_ptr[4*i + 2];
        digest[4*i + 2] = tag_state_ptr[4*i + 1];
        digest[4*i + 3] = tag_state_ptr[4*i + 0];
    }
} 

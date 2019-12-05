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
#include <inttypes.h>
#include "cipher.h"
#include "constants.h"
#include "util.h"
 
void Finalize(uint8_t *state, uint8_t *digest)
{
    /* Add code for finalization here*/

    /* At this point in SipHash, all the blocks of data are processed.
     * The last block will be processed in finalization
     */
    siphash_state_t *siphash_state;
    siphash_state = (siphash_state_t *)state;
    uint64_t *internal_msg = (uint64_t *)siphash_state->chunk;
    uint64_t v0=0, v1=0, v2=0, v3=0;
    uint8_t i;

    v0 = siphash_state->state[0];
    v1 = siphash_state->state[1];
    v2 = siphash_state->state[2];
    v3 = siphash_state->state[3];

    /* Take care of a block to be padded */
    /* last block should conatain only one byte */
    *(internal_msg) |= ((uint64_t)siphash_state->processed_msg_size) << 56;

    v3 ^= *(internal_msg);

    for (i = 0; i < NO_OF_ROUNDS; i++)
    {
        SIPROUND;
    }

    v0 ^= *(internal_msg);

    *(internal_msg) = 0;
    siphash_state->processed_msg_size=0;
    siphash_state->chunk_idx=0;

    /* finalization procedures */
    v2 ^= 0xee;

    for (i = 0; i < D_ROUNDS; ++i)
    {
        SIPROUND;
    }

    U64TO8_LE(digest, (v0 ^ v1 ^ v2 ^ v3));
    
    v1 ^= 0xdd;

    for (i = 0; i < D_ROUNDS; ++i)
    {
        SIPROUND;
    }

    U64TO8_LE((digest + 8), (v0 ^ v1 ^ v2 ^ v3));

    /* Assing v0,v1,v2,v3 to the state */
    siphash_state->state[0] = v0;
    siphash_state->state[1] = v1;
    siphash_state->state[2] = v2;
    siphash_state->state[3] = v3;
}
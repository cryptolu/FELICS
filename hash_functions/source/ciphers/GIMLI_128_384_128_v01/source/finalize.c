/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2017 by Virat Shejwalkar <virat.shejwalkar@uni.lu0>
 ** This file is part of FELICS.
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
#include <stdio.h>
#include <inttypes.h>

#include "cipher.h"
#include "constants.h"
#include "util.h"

void Finalize(uint8_t *state, uint8_t *digest)
{
    /* Add code for finalization here*/
    gimli_state_t *gimli_state;
    uint8_t i;
    
    gimli_state = (gimli_state_t *)state;
    uint8_t digest_size = DIGEST_SIZE;

    /* Check if padding is required based on chunk_idx */
    if(gimli_state->chunk_idx > 0)
    {
        /* message block should be xored with the state */
        for(i=0; i<gimli_state->chunk_idx; i++)
        {
            state[i] ^= gimli_state->chunk[i];
            gimli_state->chunk[i] = 0;
        }
    }

    state[gimli_state->chunk_idx] ^= 0x1F;
    // Add the second bit of padding
    state[BLOCK_SIZE-1] ^= 0x80;
    // Switch to the squeezing phase
    gimli(gimli_state->state);
    gimli_state->chunk_idx=0;

    while(digest_size > 0)
    {
        for(i=0; i<BLOCK_SIZE; i++)
        {
            memcpy(digest, state, digest_size);
        }
            
        digest += BLOCK_SIZE;
        digest_size -= BLOCK_SIZE;
        if (digest_size > 0)
        {
            gimli(gimli_state->state);
        }
    }
} 
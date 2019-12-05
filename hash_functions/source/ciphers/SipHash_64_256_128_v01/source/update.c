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
#include "util.h"

void Update(uint8_t *state, uint8_t *message_block, uint16_t message_len)
{
    /* Add compression code here 
     * This should be for processing of one message_block of length BLOCK_SIZE.
     */

    /* In SipHash even when one block of data is passed, two blocks will be processed
     * due to its padding specification.
     */
    uint64_t v0=0, v1=0, v2=0, v3=0;
    siphash_state_t *siphash_state;
    siphash_state = (siphash_state_t *)state;
    uint64_t *internal_msg = (uint64_t *)siphash_state->chunk;
    uint8_t i;
    uint8_t n_free_positions;
    uint8_t *msg_ptr;
    uint8_t input_bytes = message_len;

    msg_ptr = message_block;

    while(input_bytes > 0)
    {
        n_free_positions = 8 - siphash_state->chunk_idx;

        if (input_bytes <= n_free_positions)
        {
            /* we have enough space in chunk to copy the remaining of the message */
            for (i = 0; i < input_bytes; i++)
            {
                siphash_state->chunk[siphash_state->chunk_idx + i] = msg_ptr[i];
            }
            siphash_state->chunk_idx += input_bytes;
            siphash_state->processed_msg_size += input_bytes;
            input_bytes = 0;
        }
        else
        {
            /* let's copy only n_free_positions bytes from the message then */
            for (i = 0; i < n_free_positions; i++)
            {
                siphash_state->chunk[siphash_state->chunk_idx + i] = msg_ptr[i];
            }
            input_bytes -= n_free_positions;
            msg_ptr += n_free_positions;
            siphash_state->processed_msg_size += n_free_positions;
            siphash_state->chunk_idx = 8;
        }

        if (siphash_state->chunk_idx == 8)
        {
            v0 = siphash_state->state[0];
            v1 = siphash_state->state[1];
            v2 = siphash_state->state[2];
            v3 = siphash_state->state[3];

            v3 ^= *(internal_msg);

            for (i = 0; i < NO_OF_ROUNDS; i++)
            {
                SIPROUND;
            }

            v0 ^= *(internal_msg);

            siphash_state->state[0] = v0;
            siphash_state->state[1] = v1;
            siphash_state->state[2] = v2;
            siphash_state->state[3] = v3;

            *(internal_msg) = 0;
            siphash_state->chunk_idx = 0;
        }
    }

}
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

void Update(uint8_t *state, uint8_t *message_block, uint16_t message_len)
{
    gimli_state_t *gimli_state;
    uint16_t remaining_bytes;
    uint8_t *msg_ptr;
    uint8_t n_free_positions;
    uint8_t i;

    gimli_state = (gimli_state_t *)state;
    remaining_bytes = message_len;
    msg_ptr = message_block;

    while(remaining_bytes > 0)
    {
        n_free_positions = 16 - gimli_state->chunk_idx;

        if (remaining_bytes <= n_free_positions)
        {
            /* we have enough space in chunk to copy the remaining of the message */
            for (i = 0; i < remaining_bytes; i++)
            {
                gimli_state->chunk[gimli_state->chunk_idx + i] = msg_ptr[i];
            }
            gimli_state->chunk_idx += remaining_bytes;
            remaining_bytes = 0;
        }
        else
        {
            /* let's copy only n_free_positions bytes from the message then */
            for (i = 0; i < n_free_positions; i++)
            {
                gimli_state->chunk[gimli_state->chunk_idx + i] = msg_ptr[i];
            }
            remaining_bytes -= n_free_positions;
            msg_ptr += n_free_positions;
            gimli_state->chunk_idx = 16;
        }

        if (gimli_state->chunk_idx == 16)
        {
            /* message block should be xored with the state */
            for(i=0; i<16; i++)
            {
                state[i] ^= gimli_state->chunk[i];
                gimli_state->chunk[i] = 0;
            }
            
            gimli(gimli_state->state);

            gimli_state->chunk_idx = 0;
        }
    }
} 
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
#include "util.h"
 
void Update(uint8_t *state, uint8_t *message_block, uint16_t message_len)
{
    /* 
     * 
     * Add compression code here 
     * This should be for processing of one message_block of length BLOCK_SIZE.
     * message_len here is the length of the part the message not yet processed.
     *
     */
    photon_state_t *photon_state;
    photon_state = (photon_state_t *)state;
    uint16_t input_bytes, n_free_positions;
    uint8_t i;
    input_bytes = message_len;

    while(input_bytes)
    {
        n_free_positions = 2 - photon_state->chunk_idx;

        if (input_bytes <= n_free_positions)
        {
            /* we have enough space in chunk to copy the remaining of the message */
            for (i = 0; i < input_bytes; i++)
            {
                photon_state->chunk[photon_state->chunk_idx + i] = message_block[i];
            }
            photon_state->chunk_idx += input_bytes;
            input_bytes = 0;
        }
        else
        {
            /* let's copy only n_free_positions bytes from the message then */
            for (i = 0; i < n_free_positions; i++)
            {
                photon_state->chunk[photon_state->chunk_idx + i] = message_block[i];
            }
            input_bytes -= n_free_positions;
            message_block += n_free_positions;
            photon_state->chunk_idx = 2;
        }

        if(photon_state->chunk_idx == 2)
        {
            WordXorByte(photon_state->state, photon_state->chunk, 0, 0, 8*BLOCK_SIZE);
            Permutation(photon_state->state);
            memset(photon_state->chunk, 0, BLOCK_SIZE);
            photon_state->chunk_idx = 0;
        }
    }
}
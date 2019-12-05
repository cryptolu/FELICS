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
#include "blake2.h"
#include "blake2-impl.h"

void Update(uint8_t *state, uint8_t *message_block, uint16_t message_len)
{
    /* 
     * Add compression code here 
     * This should be for processing of one message_block of length BLOCK_SIZE.
     */
    blake2s_state_t *blake2s_state;
    blake2s_state = (blake2s_state_t *)state;
    uint32_t *internal_msg = (uint32_t *)blake2s_state->chunk;
    uint8_t input_bytes = message_len;
    uint8_t n_free_positions;
    uint8_t *msg_ptr;
    uint32_t V[16] ={0};
    uint32_t M[16] ={0};
    uint16_t i;

    msg_ptr = message_block;
    for(i=0; i<8; i++)
    {
        V[i] = blake2s_state->state[i];
    }

    /* Fetch the counter values from state */
    V[12] = blake2s_state->state[12];
    V[13] = blake2s_state->state[13];
    

    while(input_bytes > 0)
    {
        /* Data chunk management */
        n_free_positions = 64 - blake2s_state->chunk_idx;
        //printf("rem %d\n", blake2s_state->remaining_msg_size);
        if(input_bytes <= n_free_positions)
        {
            /* we have enough space in chunk to copy the remaining of the message */
            for (i = 0; i < input_bytes; i++)
            {
                blake2s_state->chunk[blake2s_state->chunk_idx + i] = msg_ptr[i];
            }
            blake2s_state->chunk_idx += input_bytes;
            blake2s_state->remaining_msg_size -= input_bytes;
            input_bytes = 0;

            /* Increament counter by message length being processed */
            V[12] += blake2s_state->chunk_idx;
            V[13] += (V[12] < blake2s_state->chunk_idx);

            if(blake2s_state->remaining_msg_size == 0)
            {
                /* This implies the block is last block */
                V[14] = 0xffffffff; /* f0 */
                V[15] = 0x00000000; /* f1 */

                for (i = blake2s_state->chunk_idx; i < 64; i++)
                {
                    blake2s_state->chunk[i] = 0;
                }

                blake2s_state->chunk_idx = 64;

            }
        }
        else
        {
            /* let's copy only n_free_positions bytes from the message then */
            for (i = 0; i < n_free_positions; i++)
            {
                blake2s_state->chunk[blake2s_state->chunk_idx + i] = msg_ptr[i];
            }
            
            input_bytes -= n_free_positions;
            msg_ptr += n_free_positions;
            blake2s_state->remaining_msg_size -= n_free_positions;
            blake2s_state->chunk_idx = 64;
            
            if(blake2s_state->remaining_msg_size == 0)
            {
                /* This implies the block is last block */
                V[14] = 0xffffffff; /* f0 */
                V[15] = 0x00000000; /* f1 */
            }

            /* Increament counter by message length being processed */
            V[12] += blake2s_state->chunk_idx;
            V[13] += (V[12] < blake2s_state->chunk_idx);

        }

        if(blake2s_state->chunk_idx == 64)
        {

            for(i=0; i<16; i++)
            {
                M[i] = internal_msg[i];
                internal_msg[i]=0;
            }
            
            blake2s_state->state[12] = V[12];
            blake2s_state->state[13] = V[13];

            V[ 8] = blake2s_IV[0];
            V[ 9] = blake2s_IV[1];
            V[10] = blake2s_IV[2];
            V[11] = blake2s_IV[3];
            V[12] ^= blake2s_IV[4];
            V[13] ^= blake2s_IV[5];
            V[14] ^= blake2s_IV[6];
            V[15] ^= blake2s_IV[7];


            ROUND( 0, V, M );
            ROUND( 1, V, M );
            ROUND( 2, V, M );
            ROUND( 3, V, M );
            ROUND( 4, V, M );
            ROUND( 5, V, M );
            ROUND( 6, V, M );
            ROUND( 7, V, M );
            ROUND( 8, V, M );
            ROUND( 9, V, M );

            for( i = 0; i < 8; ++i ) 
            {
                blake2s_state->state[i] = blake2s_state->state[i] ^ V[i] ^ V[i+8];
            }
            blake2s_state->chunk_idx=0;

        }
    }
}
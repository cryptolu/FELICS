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

#include "cipher.h"
#include "constants.h"
#include "blake2.h"
#include "blake2-impl.h"

void Initialize(uint8_t *state)
{
    /* Add initialization code here */

    /* blake2s_param is defined in the specification and should contain all
     * the elements listed even if they are not used.
     */
    blake2s_state_t *blake2s_state;
    blake2s_state = (blake2s_state_t *)state;
    blake2s_param P[1];
    uint8_t i;

    P->digest_length = DIGEST_SIZE;
    P->key_length    = 0;
    P->fanout        = 1;
    P->depth         = 1;

    blake2s_state->remaining_msg_size = MESSAGE_SIZE;
    for( i = 0; i < 8; ++i )
    {
        blake2s_state->state[i] = blake2s_IV[i];
    }
    
    /* h0 = IV ^ P */
    blake2s_state->state[0] ^= load32( &P[0] );
}
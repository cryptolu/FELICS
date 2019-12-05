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
#include "cipher.h"
#include "constants.h"
#include "util.h"

void Finalize(uint8_t *state, uint8_t *digest)
{
    /* Add code for finalization here*/
    photon_state_t *photon_state;
    photon_state = (photon_state_t *)state;
    uint8_t i;

    i = 0;
    /* take care of padding */
    if(photon_state->chunk_idx == 1)
    {
        photon_state->chunk[1] = 0x80;

        WordXorByte(photon_state->state, photon_state->chunk, 0, 0, 8*BLOCK_SIZE);
        Permutation(photon_state->state);
    }
    else
    {
        photon_state->chunk[0] = 0x80;
        photon_state->chunk[1] = 0x00;
        WordXorByte(photon_state->state, photon_state->chunk, 0, 0, 8*BLOCK_SIZE);
        Permutation(photon_state->state);
    }
    memset(photon_state->chunk, 0, BLOCK_SIZE);
    photon_state->chunk_idx = 0;

    while(1){
        WordToByte(photon_state->state, digest, i, min((8*BLOCK_SIZE), (8*DIGEST_SIZE)-i));
        i += 16;
        if(i >= (8*DIGEST_SIZE))
        {
            break;
        }
        Permutation(photon_state->state);
    }    

} 
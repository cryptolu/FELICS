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
#include "cipher.h"
#include "constants.h"
#include "util.h"
 
void Finalize(uint8_t *state, uint8_t *digest)
{
    /* Add code for finalization here*/

    /* At this point in SipHash, all the blocks of data are processed.
     * The last block will be processed in finalization
     */
    
    uint8_t i;
    uint64_t v0=0, v1=0, v2=0, v3=0;

    for(i=0; i<8; i++)
    {
        v0 |= ((uint64_t)state[i] << 8*i);
        v1 |= ((uint64_t)state[8+i] << 8*i);
        v2 |= ((uint64_t)state[16+i] << 8*i);
        v3 |= ((uint64_t)state[24+i] << 8*i);
    }

    v2 ^= 0xff;

    for (i = 0; i < D_ROUNDS; ++i)
    {
        SIPROUND;
    }

    U64TO8_LE(digest, (v0 ^ v1 ^ v2 ^ v3));
    
    /* Assing v0,v1,v2,v3 to the state */
    for (i=0;i<8;i++)
    {
        state[i]=(uint8_t)(v0>>(8*i));
        state[8+i]=(uint8_t)(v1>>(8*i));
        state[16+i]=(uint8_t)(v2>>(8*i));
        state[24+i]=(uint8_t)(v3>>(8*i));
    } 
}
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
#include <inttypes.h>
#include "cipher.h"
#include "constants.h"
#include "util.h"

void Initialize(uint8_t *state)
{
    uint8_t i;

    uint64_t v0 = 0x736f6d6570736575ULL;
    uint64_t v1 = 0x646f72616e646f6dULL;
    uint64_t v2 = 0x6c7967656e657261ULL;
    uint64_t v3 = 0x7465646279746573ULL;

    uint64_t k0 = U8TO64_LE(Key);
    uint64_t k1 = U8TO64_LE(Key + 8);

    v3 ^= k1;
    v2 ^= k0;
    v1 ^= k1;
    v0 ^= k0;

    /*
    printf("0x%"PRIx64"\n", v0);
    printf("0x%"PRIx64"\n", v1);
    printf("0x%"PRIx64"\n", v2);
    printf("0x%"PRIx64"\n", v3);
    printf("\n");
    */
    /* Assing v0,v1,v2,v3 to the state */
    for (i=0;i<8;i++)
    {
        state[i]=(uint8_t)(v0>>(8*i));
        state[8+i]=(uint8_t)(v1>>(8*i));
        state[16+i]=(uint8_t)(v2>>(8*i));
        state[24+i]=(uint8_t)(v3>>(8*i));
    }
}
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
#include "permute.h"

void Initialize(uint8_t *state, const uint8_t *key, const uint8_t *nonce)
{
    uint8_t j, t;
    uint8_t tem;

    //initialize the state to 0
    for (j = 0; j < STATE_SIZE; j++) state[j] = 0;

    //run the cipher for 1792 steps

    //load the key
    for (j = 0;  j < 16;  j = j+1)
    {
        acorn128_8steps(state, (uint8_t *)&(key[j]), &tem, 0xff, 0xff, 1);
    }

    //load the nonce
    for (j = 16;  j < 32;  j = j+1)
    {
        acorn128_8steps(state, (uint8_t *)&(nonce[j-16]), &tem, 0xff, 0xff, 1);
    }

    //bit "1" is padded
    for (j = 32;  j < 33; j++)
    {
        t = key[j&0xf] ^ 1;
        acorn128_8steps(state, &t, &tem, 0xff, 0xff, 1);
    }

    for (j = 33;  j < 40; j++)
    {
        acorn128_8steps(state, (uint8_t *)&(key[j&0xf]), &tem, 0xff, 0xff, 1);
    }

    for (j = 40;  j < 224; j=j+1)
    {
        acorn128_8steps(state, (uint8_t *)&(key[j&0xf]), &tem, 0xff, 0xff, 1);
    }
}

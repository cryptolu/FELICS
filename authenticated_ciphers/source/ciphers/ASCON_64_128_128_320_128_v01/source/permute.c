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
#include "permute.h"
#include "cipher.h"
#include "constants.h"

#define ROTR(x,n) (((x)>>(n))|((x)<<(64-(n))))

uint64_t U64BIG(uint64_t x) {
    return ((ROTR(x, 8) & (0xFF000000FF000000UL)) |
            (ROTR(x, 24) & (0x00FF000000FF0000UL)) |
            (ROTR(x, 40) & (0x0000FF000000FF00UL)) |
            (ROTR(x, 56) & (0x000000FF000000FFUL)));
}

#ifdef MSP
void __attribute__ ((optimize(0))) permutation(uint8_t *state, uint8_t rounds)
#else
void permutation(uint8_t *state, uint8_t rounds)
#endif
{
    uint64_t t0, t1, t2, t3, t4;
    uint64_t *state_64 = (uint64_t *)state;
    uint8_t i;

    state_64[0] = U64BIG(state_64[0]);
    state_64[1] = U64BIG(state_64[1]);
    state_64[2] = U64BIG(state_64[2]);
    state_64[3] = U64BIG(state_64[3]);
    state_64[4] = U64BIG(state_64[4]);

    for (i = pA - rounds; i < pA; ++i) {
        // addition of round constant
        state_64[2] ^= ((0xfull - i) << 4) | i;

        // substitution layer
        state_64[0] ^= state_64[4];
        state_64[4] ^= state_64[3];
        state_64[2] ^= state_64[1];
        t0 = state_64[0];
        t1 = state_64[1];
        t2 = state_64[2];
        t3 = state_64[3];
        t4 = state_64[4];
        t0 = ~t0;
        t1 = ~t1;
        t2 = ~t2;
        t3 = ~t3;
        t4 = ~t4;
        t0 &= state_64[1];
        t1 &= state_64[2];
        t2 &= state_64[3];
        t3 &= state_64[4];
        t4 &= state_64[0];
        state_64[0] ^= t1;
        state_64[1] ^= t2;
        state_64[2] ^= t3;
        state_64[3] ^= t4;
        state_64[4] ^= t0;
        state_64[1] ^= state_64[0];
        state_64[0] ^= state_64[4];
        state_64[3] ^= state_64[2];
        state_64[2] = ~state_64[2];

        // linear diffusion layer
        state_64[0] ^= ROTR(state_64[0], 19) ^ ROTR(state_64[0], 28);
        state_64[1] ^= ROTR(state_64[1], 61) ^ ROTR(state_64[1], 39);
        state_64[2] ^= ROTR(state_64[2], 1) ^ ROTR(state_64[2], 6);
        state_64[3] ^= ROTR(state_64[3], 10) ^ ROTR(state_64[3], 17);
        state_64[4] ^= ROTR(state_64[4], 7) ^ ROTR(state_64[4], 41);
    }

    state_64[0] = U64BIG(state_64[0]);
    state_64[1] = U64BIG(state_64[1]);
    state_64[2] = U64BIG(state_64[2]);
    state_64[3] = U64BIG(state_64[3]);
    state_64[4] = U64BIG(state_64[4]);
}

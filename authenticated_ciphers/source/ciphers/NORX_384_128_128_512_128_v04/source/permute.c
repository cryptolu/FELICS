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

#include "permute.h"
#include "constants.h"
#include <stdio.h>
#include <inttypes.h>

/* The nonlinear primitive */
#define H(A, B) ( ( (A) ^ (B) ) ^ ( ( (A) & (B) ) << 1) )
#define ROTR(x, c) ( ((x) >> (c)) | ((x) << (32 - (c))) )

/* The quarter-round */
#define G(A, B, C, D)                               \
do                                                  \
{                                                   \
    (A) = H(A, B); (D) ^= (A); (D) = ROTR((D), 8);  \
    (C) = H(C, D); (B) ^= (C); (B) = ROTR((B), 11); \
    (A) = H(A, B); (D) ^= (A); (D) = ROTR((D), 16); \
    (C) = H(C, D); (B) ^= (C); (B) = ROTR((B), 31); \
} while (0)

/* The full round */
void F(uint32_t S[16]) {
    /* Column step */
    G(S[0], S[4], S[8], S[12]);
    G(S[1], S[5], S[9], S[13]);
    G(S[2], S[6], S[10], S[14]);
    G(S[3], S[7], S[11], S[15]);
    /* Diagonal step */
    G(S[0], S[5], S[10], S[15]);
    G(S[1], S[6], S[11], S[12]);
    G(S[2], S[7], S[8], S[13]);
    G(S[3], S[4], S[9], S[14]);
}

/* The core permutation */
void norx_permute(uint32_t *state) {
    uint8_t i;
    for (i = 0; i < NORX_L; ++i) {
        F(state);
    }
}

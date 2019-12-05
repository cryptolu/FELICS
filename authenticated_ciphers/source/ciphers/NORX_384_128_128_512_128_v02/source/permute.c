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
/* The full round */
void F(norx_word_t S[16]) {
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
void norx_permute(norx_state_t state) {
    uint8_t i;
    norx_word_t *S = state->S;

    for (i = 0; i < NORX_L; ++i) {
        F(S);
    }
}

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
#include "data_types.h"

void TagGeneration(uint8_t *state, uint8_t *tag) {
    u32 t0_o, t0_e, t1_o, t1_e; //temporary variables, used on COMPRESS_LONG
    u32 x0_o, x1_o, x2_o, x3_o, x4_o;   //one side of the sponge
    u32 x0_e, x1_e, x2_e, x3_e, x4_e;   //other side o the sponge
    //move state into local variables
    x0_o = state[0] | (state[1] << 8) | (state[2] << 16) | (state[3] << 24);
    x0_e = state[4] | (state[5] << 8) | (state[6] << 16) | (state[7] << 24);
    x1_o = state[8] | (state[9] << 8) | (state[10] << 16) | (state[11] << 24);
    x1_e = state[12] | (state[13] << 8) | (state[14] << 16) | (state[15] << 24);
    x2_o = state[16] | (state[17] << 8) | (state[18] << 16) | (state[19] << 24);
    x2_e = state[20] | (state[21] << 8) | (state[22] << 16) | (state[23] << 24);
    x3_o = state[24] | (state[25] << 8) | (state[26] << 16) | (state[27] << 24);
    x3_e = state[28] | (state[29] << 8) | (state[30] << 16) | (state[31] << 24);
    x4_o = state[32] | (state[33] << 8) | (state[34] << 16) | (state[35] << 24);
    x4_e = state[36] | (state[37] << 8) | (state[38] << 16) | (state[39] << 24);

    EXPAND_U32(t1_e, x3_o >> 16, x3_e >> 16);
    ((u32 *) tag)[0] = U32BIG(t1_e);
    EXPAND_U32(t1_e, x3_o, x3_e);
    ((u32 *) tag)[1] = U32BIG(t1_e);
    EXPAND_U32(t1_e, x4_o >> 16, x4_e >> 16);
    ((u32 *) tag)[2] = U32BIG(t1_e);
    EXPAND_U32(t1_e, x4_o, x4_e);
    ((u32 *) tag)[3] = U32BIG(t1_e);
    //*clen = mlen + KEY_SIZE;
    // End of ASCON team code

    // move data into *state
#define C(s, idx, x)({   \
        s[idx  ] = x    & 0xff;\
        s[idx+1] = x>>8  & 0xff;\
        s[idx+2] = x>>16 & 0xff;\
        s[idx+3] = x>>24 & 0xff;\
    })

    C(state, 0, x0_o);
    C(state, 4, x0_e);
    C(state, 8, x1_o);
    C(state, 12, x1_e);
    C(state, 16, x2_o);
    C(state, 20, x2_e);
    C(state, 24, x3_o);
    C(state, 28, x3_e);
    C(state, 32, x4_o);
    C(state, 36, x4_e);

#undef C
}

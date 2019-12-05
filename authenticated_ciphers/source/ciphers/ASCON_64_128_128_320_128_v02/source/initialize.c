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
#include "data_types.h"

    void Initialize(uint8_t *state, const uint8_t *key, const uint8_t *nonce) {
        //variables
        u32 t0_o, t0_e, t1_o, t1_e; //temporary variables, used on COMPRESS_LONG
        u32 K0_o, K0_e, K1_o, K1_e; //key variables
        u32 N0_o, N0_e, N1_o, N1_e; //nonce variables
        u32 x0_o, x1_o, x2_o, x3_o, x4_o;   //one side of the sponge
        u32 x0_e, x1_e, x2_e, x3_e, x4_e;   //other side o the sponge
        //compression
         COMPRESS_BYTE_ARRAY(key, K0_o, K0_e);
         COMPRESS_BYTE_ARRAY(key + 8, K1_o, K1_e);
         COMPRESS_BYTE_ARRAY(nonce, N0_o, N0_e);
         COMPRESS_BYTE_ARRAY(nonce + 8, N1_o, N1_e);

        // initialization - ASCON Team code
         t1_e = (u32) ((KEY_SIZE * 8) << 24 | (RATE *
                        8) << 16 | PA_ROUNDS << 8 | PB_ROUNDS << 0);
         t1_o = t1_e >> 1;
         COMPRESS_LONG(t1_e);
         COMPRESS_LONG(t1_o);
         x0_e = t1_e << 16;
         x0_o = t1_o << 16;
         x1_o = K0_o;
         x1_e = K0_e;
         x2_e = K1_e;
         x2_o = K1_o;
         x3_e = N0_e;
         x3_o = N0_o;
         x4_e = N1_e;
         x4_o = N1_o;
         P12_32;
         x3_e ^= K0_e;
         x3_o ^= K0_o;
         x4_e ^= K1_e;
         x4_o ^= K1_o;
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

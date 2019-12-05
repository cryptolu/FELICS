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

#ifndef CONSTANTS_H
#define CONSTANTS_H

#include "data_types.h"

#define BLOCK_SIZE 8
#define KEY_SIZE 16
#define NONCE_SIZE 16
#define STATE_SIZE 40
#define TAG_SIZE 16

#define TEST_MESSAGE_SIZE BLOCK_SIZE
#define TEST_ASSOCIATED_DATA_SIZE BLOCK_SIZE

#define CRYPTO_NSECBYTES 0
#define CRYPTO_ABYTES 16
#define CRYPTO_NOOVERLAP 1

#define LITTLE_ENDIAN

#define RATE (64 / 8)
#define PA_ROUNDS 12
#define PB_ROUNDS 6


#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))

/*
 * #ifdef BIG_ENDIAN
 * #define EXT_BYTE32(x,n) ((u8)((u32)(x)>>(8*(n))))
 * #define INS_BYTE32(x,n) ((u32)(x)<<(8*(n)))
 * #define U32BIG(x) (x)
 * #endif
 */

#ifdef LITTLE_ENDIAN
#define EXT_BYTE32(x,n) ((u8)((u32)(x)>>(8*(3-(n)))))
#define INS_BYTE32(x,n) ((u32)(x)<<(8*(3-(n))))
#define U32BIG(x) \
        ((ROTR32(x,  8) & (0xFF00FF00)) | \
        ((ROTR32(x, 24) & (0x00FF00FF))))
#endif


#define EXPAND_SHORT(x) ({\
    x &= 0x0000ffff;\
    x = (x | (x << 8)) & 0x00ff00ff;\
    x = (x | (x << 4)) & 0x0f0f0f0f;\
    x = (x | (x << 2)) & 0x33333333;\
    x = (x | (x << 1)) & 0x55555555;\
    })

#define EXPAND_U32(var,var_o,var_e) ({\
   /*var 32-bit, and var_o/e 16-bit*/\
   t0_e = (var_e);\
   t0_o = (var_o);\
   EXPAND_SHORT(t0_e);\
   EXPAND_SHORT(t0_o);\
   var = t0_e | (t0_o << 1);\
   })


#define COMPRESS_LONG(x) ({\
    x &= 0x55555555;\
    x = (x | (x >> 1)) & 0x33333333;\
    x = (x | (x >> 2)) & 0x0f0f0f0f;\
    x = (x | (x >> 4)) & 0x00ff00ff;\
    x = (x | (x >> 8)) & 0x0000ffff;\
    })


#define COMPRESS_U32(var,var_o,var_e) ({\
  /*var 32-bit, and var_o/e 16-bit*/\
  var_e = var;\
  var_o = var_e >> 1;\
  COMPRESS_LONG(var_e);\
  COMPRESS_LONG(var_o);\
  })

#define COMPRESS_BYTE_ARRAY(a,var_o,var_e) ({\
   var_e = U32BIG(((u32*)(a))[1]);\
   var_o = var_e >> 1;\
   COMPRESS_LONG(var_e);\
   COMPRESS_LONG(var_o);\
   t1_e = U32BIG(((u32*)(a))[0]);\
   t1_o = t1_e >> 1;\
   COMPRESS_LONG(t1_e);\
   COMPRESS_LONG(t1_o);\
   var_e |= t1_e << 16;\
   var_o |= t1_o << 16;\
   })

static const int R_O[5][2] = { {9, 14}, {19, 30}, {0, 3}, {5, 8}, {3, 20} };
static const int R_E[5][2] = { {10, 14}, {20, 31}, {1, 3}, {5, 9}, {4, 21} };

#endif

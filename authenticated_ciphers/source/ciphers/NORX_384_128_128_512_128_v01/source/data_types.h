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

#ifndef DATA_TYPES_H
#define DATA_TYPES_H

#include "cipher.h"


#include <stddef.h>
#include <stdint.h>
#include "constants.h"


typedef uint32_t norx_word_t;

typedef struct norx_state__ {
    norx_word_t S[16];
} norx_state_t[1];

#define NORX_N (NORX_W *  4)    /* Nonce size */
#define NORX_K (NORX_W *  4)    /* Key size */
#define NORX_B (NORX_W * 16)    /* Permutation width */
#define NORX_C (NORX_W *  4)    /* Capacity */
#define NORX_R (NORX_B - NORX_C)    /* Rate */

#define LOAD load32
#define STORE store32

/* Rotation constants */
#define R0  8
#define R1 11
#define R2 16
#define R3 31

/* The nonlinear primitive */
#define H(A, B) ( ( (A) ^ (B) ) ^ ( ( (A) & (B) ) << 1) )

/* The quarter-round */
#define G(A, B, C, D)                               \
do                                                  \
{                                                   \
    (A) = H(A, B); (D) ^= (A); (D) = ROTR((D), R0); \
    (C) = H(C, D); (B) ^= (C); (B) = ROTR((B), R1); \
    (A) = H(A, B); (D) ^= (A); (D) = ROTR((D), R2); \
    (C) = H(C, D); (B) ^= (C); (B) = ROTR((B), R3); \
} while (0)

typedef enum tag__ {
    HEADER_TAG = 0x01,
    PAYLOAD_TAG = 0x02,
    TRAILER_TAG = 0x04,
    FINAL_TAG = 0x08,
    BRANCH_TAG = 0x10,
    MERGE_TAG = 0x20
} tag_t;


#endif /* DATA_TYPES_H */

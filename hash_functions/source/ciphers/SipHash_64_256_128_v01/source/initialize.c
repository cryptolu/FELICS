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
    siphash_state_t *siphash_state;
    siphash_state = (siphash_state_t *)state;
    
    siphash_state->state[0] = 0x736f6d6570736575ULL;
    siphash_state->state[1] = 0x646f72616e646f6dULL;
    siphash_state->state[2] = 0x6c7967656e657261ULL;
    siphash_state->state[3] = 0x7465646279746573ULL;

    uint64_t k0 = U8TO64_LE(Key);
    uint64_t k1 = U8TO64_LE(Key + 8);

    siphash_state->state[3] ^= k1;
    siphash_state->state[2] ^= k0;
    siphash_state->state[1] ^= k1;
    siphash_state->state[0] ^= k0;

    siphash_state->state[1] ^= 0xee;
}
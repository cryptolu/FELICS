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
#include <stdio.h>
#include <string.h>

#include "cipher.h"
#include "constants.h"
#include "permute.h"

void Finalize(uint8_t *state, uint8_t *key) {
    /* Add code for finalization here */

    uint32_t *state_32 = (uint32_t *)state;
    uint32_t *key_32 = (uint32_t *)key;

    state_32[15] ^= 0x08;

    norx_permute(state_32);

    state_32[12] ^= key_32[0];
    state_32[13] ^= key_32[1];
    state_32[14] ^= key_32[2];
    state_32[15] ^= key_32[3];

    norx_permute(state_32);

    state_32[12] ^= key_32[0];
    state_32[13] ^= key_32[1];
    state_32[14] ^= key_32[2];
    state_32[15] ^= key_32[3];

}

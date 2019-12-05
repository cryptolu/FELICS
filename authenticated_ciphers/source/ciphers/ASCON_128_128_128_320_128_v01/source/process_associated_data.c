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
#include "cipher.h"
#include "constants.h"
#include "permute.h"

void ProcessAssociatedData(uint8_t *state, uint8_t *associatedData,
        uint32_t associated_data_length) {
    uint8_t i, j;

    uint8_t last_block_size = (associated_data_length % BLOCK_SIZE);

    if ((associated_data_length / BLOCK_SIZE) != 0) {
        for (i = 0; i < (associated_data_length / BLOCK_SIZE); i++) {
            for (j = 0; j < BLOCK_SIZE; j++) {
                state[j] ^= associatedData[i * BLOCK_SIZE + j];
            }
            permutation(state, pB);
        }
    }

    /* This is when padding to associated data is required */
    for (i = 0; i < last_block_size; i++) {
        state[i] ^=
                associatedData[associated_data_length - last_block_size + i];
    }

    state[last_block_size] ^= 0x80;
    permutation(state, pB);
    state[STATE_SIZE - 1] ^= 1;
}

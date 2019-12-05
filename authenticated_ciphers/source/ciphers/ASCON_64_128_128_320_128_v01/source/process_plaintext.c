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
#include <stdlib.h>

#include "cipher.h"
#include "constants.h"
#include "permute.h"

void ProcessPlaintext(uint8_t *state, uint8_t *message, uint32_t message_length) {
    uint8_t i, j;
    uint8_t pt_block_num = (message_length / BLOCK_SIZE);
    uint8_t last_block_size = (message_length % BLOCK_SIZE);

    for (i = 0; i < pt_block_num; ++i) {
        for (j = 0; j < BLOCK_SIZE; ++j) {
            state[j] ^= message[i * BLOCK_SIZE + j];
            message[i * BLOCK_SIZE + j] = state[j];
        }
        permutation(state, pB);
    }

    for (j = 0; j < last_block_size; ++j) {
        state[j] ^= message[message_length - last_block_size + j];
    }

    state[last_block_size] ^= 0x80;

    for (j = 0; j < last_block_size; ++j) {
        message[(pt_block_num) * BLOCK_SIZE + j] = state[j];
    }
}

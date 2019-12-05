/*
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
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "cipher.h"
#include "constants.h"
#include "permute.h"

void ProcessCiphertext(uint8_t *state, uint8_t *message, uint32_t message_length) {
    uint8_t i, j, tempPlaintextByte;
    uint8_t pt_block_num = (message_length / BLOCK_SIZE);
    uint8_t last_block_size = (message_length % BLOCK_SIZE);
    uint8_t temp_ciphertext[last_block_size];

    if (last_block_size) {
        for (i = 0; i < last_block_size; ++i) {
            temp_ciphertext[i] = message[(pt_block_num) * BLOCK_SIZE + i];
        }
    }

    for (i = 0; i < pt_block_num; ++i) {
        for (j = 0; j < BLOCK_SIZE; ++j) {
            tempPlaintextByte = state[j] ^ message[i * BLOCK_SIZE + j];
            state[j] = message[i * BLOCK_SIZE + j];
            message[i * BLOCK_SIZE + j] = tempPlaintextByte;
        }
        permutation(state, pB);
    }

    if (last_block_size) {
        for (j = 0; j < last_block_size; ++j) {
            tempPlaintextByte =
                    state[j] ^ message[(pt_block_num) * BLOCK_SIZE + j];
            message[pt_block_num * BLOCK_SIZE + j] = tempPlaintextByte;
        }

        for (j = 0; j < last_block_size; ++j) {
            state[j] = temp_ciphertext[j];
        }
    }

    state[last_block_size] ^= 0x80;
}

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
#include <string.h>

#include "cipher.h"
#include "constants.h"
#include "permute.h"

void norx_encrypt_block(uint32_t *state, uint8_t *out, const uint8_t *in) {
    uint32_t *in_32 = (uint32_t *)in;
    uint32_t *out_32 = (uint32_t *)out;
    uint8_t i;

    state[15] ^= 0x02;
    norx_permute(state);

    for (i = 0; i < 12; ++i) {
        state[i] ^= in_32[i];
        out_32[i] = state[i];
    }
}

void norx_encrypt_lastblock(uint32_t *state, uint8_t *out, const uint8_t *in,
        uint8_t inlen) {
    uint8_t lastblock[BLOCK_SIZE] = { 0 };

    /* Padding part */
    memcpy(lastblock, in, inlen);
    lastblock[inlen] = 0x01;
    lastblock[BLOCK_SIZE - 1] |= 0x80;

    norx_encrypt_block(state, lastblock, lastblock);
    memcpy(out, lastblock, inlen);
}

void ProcessPlaintext(uint8_t *state, uint8_t *message, uint32_t message_length) {

    if (message_length > 0) {

#if NORX_P == 1                 /* Sequential encryption/decryption */

        uint32_t *state_32 = (uint32_t *)state;
        uint8_t temp_block[BLOCK_SIZE];
        uint8_t i;

        while (message_length >= BLOCK_SIZE) {

            norx_encrypt_block(state_32, temp_block, message);

            for (i = 0; i < BLOCK_SIZE; i++) {
                *(message + i) = *(temp_block + i);
            }

            message_length -= BLOCK_SIZE;
            message += BLOCK_SIZE;

        }

        norx_encrypt_lastblock(state_32, temp_block, message, message_length);

        for (i = 0; i < (message_length % BLOCK_SIZE); i++) {
            *(message + i) = *(temp_block + i);
        }
#else
#error "This implementation doesn't offer support for multilane payload processing (NORX_P != 1)!"
#endif /* NORX_P */

    }
}

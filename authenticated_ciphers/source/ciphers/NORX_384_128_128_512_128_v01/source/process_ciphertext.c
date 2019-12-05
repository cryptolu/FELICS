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
#include "norx_util.h"

void norx_decrypt_lastblock(norx_state_t state, uint8_t *out, const uint8_t *in,
        size_t inlen) {
    norx_word_t *S = state->S;
    uint8_t lastblock[BLOCK_SIZE];
    size_t i;

    S[15] ^= PAYLOAD_TAG;
    norx_permute(state);

    for (i = 0; i < 12; ++i) {
        STORE(lastblock + i * 4, S[i]);
    }

    memcpy(lastblock, in, inlen);
    lastblock[inlen] ^= 0x01;
    lastblock[BYTES(NORX_R) - 1] ^= 0x80;

    for (i = 0; i < WORDS(NORX_R); ++i) {
        const norx_word_t c = LOAD(lastblock + i * BYTES(NORX_W));
        STORE(lastblock + i * BYTES(NORX_W), S[i] ^ c);
        S[i] = c;
    }

    memcpy(out, lastblock, inlen);
    burn(lastblock, 0, sizeof lastblock);
}

void norx_decrypt_block(norx_state_t state, uint8_t *out, const uint8_t *in) {
    size_t i;
    norx_word_t *S = state->S;

    S[15] ^= PAYLOAD_TAG;
    norx_permute(state);

    for (i = 0; i < WORDS(NORX_R); ++i) {
        const norx_word_t c = LOAD(in + i * BYTES(NORX_W));
        STORE(out + i * BYTES(NORX_W), S[i] ^ c);
        S[i] = c;
    }
}

void ProcessCiphertext(uint8_t *state, uint8_t *message, uint32_t message_length) {
    if (message_length > 0) {
        /* Add ciphertext processing code here */
        norx_state_t state_initialize;
        norx_word_t *S = state_initialize->S;
        uint8_t temp_block[BLOCK_SIZE];
        uint8_t i;

        /* Shift data from input state to state_initialize */
        for (i = 0; i < 16; ++i) {
            S[i] = ((uint32_t)state[4 * i + 3] << 24) | ((uint32_t)state[4 * i +
                            2] << 16) | ((uint32_t)state[4 * i +
                            1] << 8) | ((uint32_t)state[4 * i] << 0);
        }

#if NORX_P == 1                 /* Sequential encryption/decryption */

        while (message_length >= BLOCK_SIZE) {
            norx_decrypt_block(state_initialize, temp_block, message);

            message_length -= BLOCK_SIZE;

            for (i = 0; i < BLOCK_SIZE; i++) {
                *(message + i) = *(temp_block + i);
            }

            message += BLOCK_SIZE;
        }
        norx_decrypt_lastblock(state_initialize, temp_block, message,
                message_length);
        for (i = 0; i < message_length; i++) {
            *(message + i) = *(temp_block + i);
        }
#if 0
#elif NORX_P > 1                /* Parallel encryption/decryption */
        norx_state_t lane[NORX_P];

        /* Initialize states + branch
         * for (i = 0; i < NORX_P; ++i) {
         * memcpy(lane[i], state_initialize, sizeof lane[i]);
         * norx_branch(lane[i], i);
         * }
         * 
         * /* Parallel payload processing */
        for (i = 0; length >= BYTES(NORX_R); ++i) {
            norx_decrypt_block(lane[i % NORX_P], temp_block, message);

            length -= BYTES(NORX_R);
            message += BYTES(NORX_R);
        }
        norx_decrypt_lastblock(lane[i % NORX_P], temp_block, message, length);

        /* Merge */
        memset(state_initialize, 0, sizeof(norx_state_t));
        for (i = 0; i < NORX_P; ++i) {
            norx_merge(state_initialize, lane[i]);
            burn(lane[i], 0, sizeof(norx_state_t));
        }

#elif NORX_P == 0               /* Unlimited parallelism */

        size_t lane = 0;
        norx_state_t sum;
        norx_state_t state2;

        memset(sum, 0, sizeof(norx_state_t));

        while (length >= BYTES(NORX_R)) {
            /* branch */
            memcpy(state2, state_initialize, sizeof(norx_state_t));
            norx_branch(state2, lane++);
            /* decrypt
             * norx_decrypt_block(state2, temp_block, message);
             * 
             * /* merge
             * norx_merge(sum, state2);
             * 
             * length -= BYTES(NORX_R);
             * message    += BYTES(NORX_R);
             * }
             * 
             * /* last block, 0 <= length < BYTES(NORX_R) */

            /* branch */
            memcpy(state2, state_initialize, sizeof(norx_state_t));
            norx_branch(state2, lane++);

            /* decrypt */
            norx_decrypt_lastblock(state2, temp_block, message, length);

            /* merge */
            norx_merge(sum, state2);

            memcpy(state_initialize, sum, sizeof(norx_state_t));
            burn(state2, 0, sizeof(norx_state_t));
            burn(sum, 0, sizeof(norx_state_t));
#endif

#else
#error "Constraint: 0 \\leq NORX_P \\leq 255"
#endif /* NORX_P */

        /* Shift data from state_initialize to state */
        for (i = 0; i < 16; ++i) {
            state[4 * i] = (uint8_t)(state_initialize->S[i] >> 0);
            state[4 * i + 1] = (uint8_t)(state_initialize->S[i] >> 8);
            state[4 * i + 2] = (uint8_t)(state_initialize->S[i] >> 16);
            state[4 * i + 3] = (uint8_t)(state_initialize->S[i] >> 24);
        }
    }
}

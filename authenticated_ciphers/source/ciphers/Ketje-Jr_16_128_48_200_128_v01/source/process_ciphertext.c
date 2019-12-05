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
#include "keccak_add_byte.h"
#include "keccak_add_bytes.h"
#include "keccak_extract_and_add_bytes.h"
#include "keccak_round.h"
#include "ketje_state_add_byte.h"
#include "ketje_state_extract_byte.h"


void KetJr_UnwrapBlocks(uint8_t *state, uint8_t *ciphertext, uint8_t *plaintext,
        uint32_t nBlocks) {
    uint32_t laneIndex;

    while (nBlocks-- != 0) {
        for (laneIndex = 0; laneIndex < (BLOCK_SIZE / Ketje_LaneSize);
                ++laneIndex) {
            KeccakP200_ExtractAndAddBytes(state, ciphertext, plaintext,
                    READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[laneIndex]) *
                    Ketje_LaneSize, Ketje_LaneSize);
            KeccakP200_AddBytes(state, plaintext,
                    READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[laneIndex]) *
                    Ketje_LaneSize, Ketje_LaneSize);
            plaintext += Ketje_LaneSize;
            ciphertext += Ketje_LaneSize;
        }
        KeccakP200_AddByte(state, 0x08 | FRAMEBITS11,
                READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[BLOCK_SIZE /
                                Ketje_LaneSize]) * Ketje_LaneSize);
        KeccakP200_Permute_Nrounds(state, Ket_StepRounds);
    }
}

void ProcessCiphertext(uint8_t *state, uint8_t *message, uint32_t message_length) {
    uint32_t initial_message_len = message_length;

    /* Add ciphertext processing code here */
    uint32_t dataRemainderSize = 0;
    if (message_length) {
        unsigned int i = 0, size;
        uint8_t temp;
        uint8_t temp_plaintext[message_length];

        /*  Wrap multiple blocks except last. */
        if (message_length > BLOCK_SIZE) {
            size = ((message_length + (BLOCK_SIZE - 1)) & ~(BLOCK_SIZE - 1)) -
                    BLOCK_SIZE;
            KetJr_UnwrapBlocks(state, message, temp_plaintext,
                    size / BLOCK_SIZE);
            message_length -= size;
            message += size;
        }

        /*  Add remaining data */
        while (i < message_length) {
            temp = *(message++) ^ KetJr_StateExtractByte(state,
                    dataRemainderSize);
            *(temp_plaintext + size + i) = temp;
            i++;
            KetJr_StateAddByte(state, temp, dataRemainderSize++);
        }

        message -= initial_message_len;
        for (i = 0; i < initial_message_len; ++i) {
            message[i] = temp_plaintext[i];
        }
    }

    KetJr_StateAddByte(state, FRAMEBITS10, dataRemainderSize);
    KetJr_StateAddByte(state, 0x08, BLOCK_SIZE);    /* padding */
    KeccakP200_Permute_Nrounds(state, Ket_StrideRounds);
}

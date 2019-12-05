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
#include "ketje_jr_util.h"

void KetJr_WrapBlocks(uint8_t *state, uint8_t *plaintext, uint8_t *ciphertext,
        uint32_t nBlocks) {
    uint32_t laneIndex;

    while (nBlocks-- != 0) {
        for (laneIndex = 0; laneIndex < (BLOCK_SIZE / Ketje_LaneSize);
                ++laneIndex) {
            KetJr_AddBytes(state, plaintext,
                    READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[laneIndex]) *
                    Ketje_LaneSize, Ketje_LaneSize);
            if ((READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[laneIndex]) < 25)
                    &&
                    (READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[laneIndex]) +
                            Ketje_LaneSize <= 25)) {
                *(ciphertext) =
                        state[READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes
                                [laneIndex])];
            }
            plaintext += Ketje_LaneSize;
            ciphertext += Ketje_LaneSize;
        }

        if (READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[BLOCK_SIZE]) < 25) {
            state[READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[BLOCK_SIZE])] ^=
                    (0x08 | FRAMEBITS11);
        }

        KeccakP200_Permute_Nrounds(state, Ket_StepRounds);
    }
}

void ProcessPlaintext(uint8_t *state, uint8_t *message, uint32_t message_length) {
    uint32_t initial_message_len = message_length;

    /* Add plaintext processing code here */
    uint32_t dataRemainderSize = 0;
    if (message_length) {
        uint32_t i = 0, size;
        uint8_t temp;
        uint8_t temp_ciphertext[message_length];

        /*  Wrap multiple blocks except last. */
        if (message_length > BLOCK_SIZE) {
            size = ((message_length + (BLOCK_SIZE - 1)) & ~(BLOCK_SIZE - 1)) -
                    BLOCK_SIZE;
            KetJr_WrapBlocks(state, message, temp_ciphertext,
                    size / BLOCK_SIZE);
            message_length -= size;
            message += size;
        }

        /*  Add remaining data */
        while (i < message_length) {
            temp = *(message++);
            *(temp_ciphertext + size + i) =
                    temp ^ KetJr_StateExtractByte(state, dataRemainderSize);
            i++;

            if (READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes
                            [dataRemainderSize]) < 25) {
                state[READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes
                                [dataRemainderSize])] ^= temp;
            }
            dataRemainderSize++;
        }

        message -= initial_message_len;
        for (i = 0; i < initial_message_len; ++i) {
            message[i] = temp_ciphertext[i];
        }
    }

    if (READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[dataRemainderSize]) < 25) {
        state[READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[dataRemainderSize])]
                ^= FRAMEBITS10;
    }
    if (READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[BLOCK_SIZE]) < 25) {
        state[READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[BLOCK_SIZE])] ^=
                0x08;
    }

    KeccakP200_Permute_Nrounds(state, Ket_StrideRounds);
}

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
#include "ketje_state_add_byte.h"
#include "ketje_step.h"


void KetJr_FeedAssociatedDataBlocks(uint8_t *state, uint8_t *data,
        uint32_t nBlocks) {

    uint32_t laneIndex;
    do {
        for (laneIndex = 0; laneIndex < (BLOCK_SIZE / Ketje_LaneSize);
                ++laneIndex) {
            KeccakP200_AddBytes(state, data,
                    READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[laneIndex]) *
                    Ketje_LaneSize, Ketje_LaneSize);
            data += Ketje_LaneSize;
        }
        KetJr_Step(state, BLOCK_SIZE, FRAMEBITS00);
    }
    while (--nBlocks != 0);
}

void ProcessAssociatedData(uint8_t *state, uint8_t *associatedData,
        uint32_t associated_data_length) {
    /* Add associated data processing code here */
    uint32_t dataRemainderSize = 0, size;

    if (associated_data_length > BLOCK_SIZE) {
        /* size equals associated_data_length - n*BLOCK_SIZE is size > 0 */
        size = ((associated_data_length + (BLOCK_SIZE - 1)) & ~(BLOCK_SIZE -
                        1)) - BLOCK_SIZE;

        KetJr_FeedAssociatedDataBlocks(state, associatedData,
                size / BLOCK_SIZE);

        associated_data_length -= size;
        associatedData += size;
    }

    while (associated_data_length-- != 0) {
        KetJr_StateAddByte(state, *(associatedData++), dataRemainderSize++);
    }

    KetJr_Step(state, dataRemainderSize, FRAMEBITS01);
}

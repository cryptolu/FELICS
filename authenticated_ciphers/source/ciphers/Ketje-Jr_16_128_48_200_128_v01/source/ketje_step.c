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
#include "keccak_add_byte.h"
#include "keccak_round.h"
#include "ketje_step.h"


void KetJr_Step(uint8_t *state, unsigned int size, uint8_t frameAndPaddingBits) {
    KeccakP200_AddByte(state, frameAndPaddingBits,
            READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[size /
                            Ketje_LaneSize]) * Ketje_LaneSize +
            size % Ketje_LaneSize);
    KeccakP200_AddByte(state, 0x08,
            READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[BLOCK_SIZE /
                            Ketje_LaneSize]) * Ketje_LaneSize);
    KeccakP200_Permute_Nrounds(state, Ket_StepRounds);
}

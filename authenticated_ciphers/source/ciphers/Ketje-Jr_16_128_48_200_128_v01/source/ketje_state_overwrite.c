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
#include "ketje_state_overwrite.h"


void KeccakP200_OverwriteBytes(uint8_t *state, uint8_t *data,
        unsigned int offset, unsigned int length) {
    memcpy((unsigned char *)state + offset, data, length);
}

void KetJr_StateOverwrite(uint8_t *state, unsigned int offset, uint8_t *data,
        unsigned int length) {
    while (length-- != 0) {
        KeccakP200_OverwriteBytes(state, data,
                READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[offset /
                                Ketje_LaneSize]) * Ketje_LaneSize +
                offset % Ketje_LaneSize, 1);
        ++data;
        ++offset;
    }
}

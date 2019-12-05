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
#include "constants.h"
#include "ketje_jr_util.h"

uint8_t KetJr_StateExtractByte(uint8_t *state, uint8_t offset) {

    //if ((READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[offset]) < 25) &&
    //        ((READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[offset]) + 1) <=
    //                25)) {
        return state[READ_KETJE_CONST_BYTE(KetJr_StateTwistIndexes[offset])];
    //}

}

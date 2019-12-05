/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2017 University of Luxembourg
 *
 * Written in 2019 by Luan Cardoso dos Santos <luan.cardoso@uni.lu> <luancardoso@icloud.com>
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
#include "util.h"
#include "sparkle_opt.h"
#include "stdint.h"
#include "string.h" //for memcpy
/*
 The initialize function loads nonce and key into the internal state, and
 executes a SPARKLE permutation.
*/
void ProcessAssociatedData(uint8_t *state, uint8_t *associatedData, uint32_t associated_data_length)
{
    #define adlen associated_data_length
    #define ad associatedData
    if(adlen != 0){
        int constA = (adlen % BYTE(RATE) != 0) ? PADADCONST : NOPADADCONST;
        //absorption loop
        while (adlen > BYTE(RATE)){
            rho1(((uint32_t*)(state)), (uint32_t *)ad);
            RATEWHITENING(((uint32_t*)(state)));
            sparklePermutation((uint32_t*)(state), STEPSSLIM);
            ad += BYTE(RATE);
            adlen -= BYTE(RATE);
        }
        //pad lBlock
        uint32_t lBlock[WORD(RATE)];
        pad(lBlock, (u8*)(ad), (u8)(adlen));

        //process last block
        rho1((uint32_t*)(state), lBlock);
        INJECTCONST(((uint32_t*)(state)), constA);
        RATEWHITENING(((uint32_t*)(state)));
        sparklePermutation((uint32_t*)(state), STEPSBIG);
    }
}

#undef adlen
#undef ad

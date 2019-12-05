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
void Initialize(uint8_t *state, const uint8_t *key, const uint8_t *nonce)
{
    uint32_t *State = (uint32_t*)(state);
    //load nonce into state.
    for(int i=0; i<CRYPTO_NPUBWORDS; i++)
        State[i]=load32((u8 *)nonce+(4*i));
    //load key into state.
    for(int i=0; i<CRYPTO_KEYWORDS; i++)
        State[i+CRYPTO_NPUBWORDS]=load32((u8 *)(key)+(4*i));
    //Apply permutation to state
    sparklePermutation(State, STEPSBIG);
}

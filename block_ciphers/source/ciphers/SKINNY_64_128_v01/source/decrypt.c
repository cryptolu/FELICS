/*
 * SKINNY-64-128
 * @Time 2017
 * @Author luopeng(luopeng@iie.ac.cn)
 */

/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

#ifdef PC
#include <string.h>             /*necessary for memset */
#include "skinny_reference.h"
#endif

#ifdef PC
void Decrypt(uint8_t *block, uint8_t *roundKeys) {

    uint8_t state[4][4];
#ifdef NOKEYSCHEDULE
    uint8_t dummy[4][4] = { {0} };
    uint8_t keyCells[3][4][4];
    memset(keyCells, 0, 48);
#endif  /*NOKEYSCHEDULE*/
    int i, j;

    for (i = 0; i < 16; i++) {
        if (versions[ver][0] == 64) {
            if (i & 1) {
                state[i >> 2][i & 0x3] = block[i >> 1] & 0xF;
#ifdef NOKEYSCHEDULE
                keyCells[0][i >> 2][i & 0x3] = roundKeys[i >> 1] & 0xF;
                if (versions[ver][1] >= 128)
                    keyCells[1][i >> 2][i & 0x3] =
                            roundKeys[(i + 16) >> 1] & 0xF;
                if (versions[ver][1] >= 192)
                    keyCells[2][i >> 2][i & 0x3] =
                            roundKeys[(i + 32) >> 1] & 0xF;
#endif /*NOKEYSCHEDULE*/
            } else {
                state[i >> 2][i & 0x3] = (block[i >> 1] >> 4) & 0xF;
#ifdef NOKEYSCHEDULE
                keyCells[0][i >> 2][i & 0x3] = (roundKeys[i >> 1] >> 4) & 0xF;
                if (versions[ver][1] >= 128)
                    keyCells[1][i >> 2][i & 0x3] =
                            (roundKeys[(i + 16) >> 1] >> 4) & 0xF;
                if (versions[ver][1] >= 192)
                    keyCells[2][i >> 2][i & 0x3] =
                            (roundKeys[(i + 32) >> 1] >> 4) & 0xF;
#endif /*NOKEYSCHEDULE*/
            }
        } else if (versions[ver][0] == 128) {
            state[i >> 2][i & 0x3] = block[i] & 0xFF;
#ifdef NOKEYSCHEDULE
            keyCells[0][i >> 2][i & 0x3] = roundKeys[i] & 0xFF;
            if (versions[ver][1] >= 256)
                keyCells[1][i >> 2][i & 0x3] = roundKeys[i + 16] & 0xFF;
            if (versions[ver][1] >= 384)
                keyCells[2][i >> 2][i & 0x3] = roundKeys[i + 32] & 0xFF;
#endif /*NOKEYSCHEDULE*/
        }
    }

#ifdef NOKEYSCHEDULE
    for (i = versions[ver][2] - 1; i >= 0; i--) {
        AddKey(dummy, keyCells, ver);
    }
#endif /*NOKEYSCHEDULE*/

    for (i = versions[ver][2] - 1, j=0; i >= 0; i--, j++) {
        MixColumn_inv(state);
        ShiftRows_inv(state);
#ifdef NOKEYSCHEDULE
        AddKey_inv(state, keyCells, ver);
#else
        AddKeyPrecomputed(state, roundKeys + 4 * j, j, ver);
#endif /*NOKEYSCHEDULE*/
        AddConstants(state, i);
        if (versions[ver][0] == 64)
            SubCell4_inv(state);
        else
            SubCell8_inv(state);
    }

    if (versions[ver][0] == 64) {
        for (i = 0; i < 8; i++)
            block[i] =
                    ((state[(2 * i) >> 2][(2 * i) & 0x3] & 0xF) << 4) | (state[(2 * i + 1) >> 2][(2 * i + 1) & 0x3] & 0xF);
    } else if (versions[ver][0] == 128) {
        for (i = 0; i < 16; i++)
            block[i] = state[i >> 2][i & 0x3] & 0xFF;
    }
}

#endif

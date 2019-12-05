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

#include <string.h> /*necessary for memset*/
#include "skinny_reference.h"

void RunDecryptionKeySchedule(uint8_t *key, uint8_t *roundKeys) {
#ifdef NOKEYSCHEDULE
    for (int i = 0; i < 16; i++) {
        roundKeys[i] = key[i];
    }
#else
    /*uint8_t state[4][4];*/
    uint8_t dummystate[4][4]={{0}};
    uint8_t keyCells[3][4][4];
    uint8_t tmpkeySchedule[8*40]={0};
    int i;

    memset(keyCells, 0, 48);
    for(i = 0; i < 16; i++) {
        if (versions[ver][0]==64){
            if(i&1)
            {
                keyCells[0][i>>2][i&0x3] = key[i>>1]&0xF;
                if (versions[ver][1]>=128)
                    keyCells[1][i>>2][i&0x3] = key[(i+16)>>1]&0xF;
                if (versions[ver][1]>=192)
                    keyCells[2][i>>2][i&0x3] = key[(i+32)>>1]&0xF;
            }
            else
            {
                keyCells[0][i>>2][i&0x3] = (key[i>>1]>>4)&0xF;
                if (versions[ver][1]>=128)
                    keyCells[1][i>>2][i&0x3] = (key[(i+16)>>1]>>4)&0xF;
                if (versions[ver][1]>=192)
                    keyCells[2][i>>2][i&0x3] = (key[(i+32)>>1]>>4)&0xF;
            }
        }
        else if (versions[ver][0]==128){
            keyCells[0][i>>2][i&0x3] = key[i]&0xFF;
            if (versions[ver][1]>=256)
                keyCells[1][i>>2][i&0x3] = key[i+16]&0xFF;
            if (versions[ver][1]>=384)
                keyCells[2][i>>2][i&0x3] = key[i+32]&0xFF;
        }
    }

    for(i = versions[ver][2]-1; i >=0 ; i--){
        AddKey(dummystate, keyCells, ver);
    }

    /*create key schedule and store at tmpkeySchedule */
    for (int i = 0; i < versions[ver][2]; i++) {
        /*execute round key schedule procedure as dummy */
        AddKey_inv(dummystate, keyCells, ver);
        for (int i3 = 0; i3 < 3; i3++) {    /*Copy Tk1^Tk2^Tk3 */
            for (int i2 = 0; i2 < 2; i2++) {
                for (int i1 = 0; i1 < 4; i1++) {
                    tmpkeySchedule[(i * 8) + (i2 * 4 + i1)] ^=
                            keyCells[i3][i2][i1];
                }
            }
        }
    }

    /*save the tmpkeySchedule into roundKeys */
    if (versions[ver][0] == 128) {
        for (i = 0; i < 8 * versions[ver][2]; i++) {
            roundKeys[i] = tmpkeySchedule[i];
        }
    }
#endif  /*NOKEYSCHEDULE*/
}

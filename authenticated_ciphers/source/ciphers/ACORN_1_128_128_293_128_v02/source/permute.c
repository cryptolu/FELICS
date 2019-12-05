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
#include <stdio.h>
#include "permute.h"

#define maj(x,y,z)   ( ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))  )
#define ch(x,y,z)    ( ((x) & (y)) ^ ((~x) & (z)) )

// 8 steps of ACORN
// the last input parameter of this function is to indicate whether it is encryption (value1) or decryption (value 0).
void acorn128_8steps(uint8_t *state, uint8_t *plaintextbyte, uint8_t *ciphertextbyte, uint8_t cabyte, uint8_t cbbyte, uint8_t enc_dec_flag)
{
    uint8_t i,f;
    uint8_t byte_235, byte_160, byte_111, byte_66, byte_196;
    uint8_t byte_230, byte_193, byte_154, byte_107, byte_61;
    uint8_t ksbyte;

    byte_235 = (state[29] >> 3) | (state[30] << 5);
    byte_160 =  state[20];
    byte_111 = (state[13] >> 7) | (state[14] << 1);
    byte_66  = (state[8]  >> 2) | (state[9]  << 6);
    byte_196 = (state[24] >> 4) | (state[25] << 4);

    byte_230 = (state[28] >> 6) | (state[29] << 2);
    byte_193 = (state[24] >> 1) | (state[25] << 7);
    byte_154 = (state[19] >> 2) | (state[20] << 6);
    byte_107 = (state[13] >> 3) | (state[14] << 5);
    byte_61  = (state[7]  >> 5) | (state[8]  << 3);

    state[36] ^= (byte_235 ^ byte_230) << 1;
    state[37] ^= (byte_235 ^ byte_230) >> 7;

    byte_230 ^= (byte_196 ^ byte_193);
    state[28] ^= (byte_196 ^ byte_193) << 6;
    state[29] ^= (byte_196 ^ byte_193) >> 2;

    byte_193  ^= (byte_160 ^ byte_154);
    state[24] ^= (byte_160 ^ byte_154) << 1;
    state[25] ^= (byte_160 ^ byte_154) >> 7;

    byte_154  ^= (byte_111 ^ byte_107);
    state[19] ^= (byte_111 ^ byte_107) << 2;
    state[20] ^= (byte_111 ^ byte_107) >> 6;

    byte_107  ^= (byte_66 ^ byte_61);
    state[13] ^= (byte_66 ^ byte_61) << 3;
    state[14] ^= (byte_66 ^ byte_61) >> 5;


    byte_61  ^= (((state[2]  >> 7) | (state[3]  << 1)) ^ state[0]);
    state[7] ^= (((state[2]  >> 7) | (state[3]  << 1)) ^ state[0]) << 5;
    state[8] ^= ((uint8_t)((state[2]  >> 7) | (state[3]  << 1)) ^ state[0]) >> 3;

    ksbyte = ((state[1]  >> 4) | (state[2]  << 4)) ^ byte_154 ^ maj(byte_235, byte_61, byte_193) ^ ch(byte_230, byte_111, byte_66);

    if (enc_dec_flag == 1) *(ciphertextbyte) = *(plaintextbyte) ^ ksbyte;
    else if (enc_dec_flag == 0) *(plaintextbyte) = *(ciphertextbyte) ^ ksbyte;

    f = state[0] ^ (~byte_107) ^ maj(((state[30] >> 4) | (state[31] << 4)), ((state[2]  >> 7) | (state[3]  << 1)), byte_160) ^ (cabyte & byte_196) ^ (cbbyte & ksbyte);

    f ^= *(plaintextbyte+i);

    state[36] ^= (f << 5);
    state[37] ^= (f >> 3);

    for (i = 0; i < 37; i++) state[i] = state[i+1];
    state[37] = 0;
}



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
#include "permute.h"

#define maj(x,y,z)   ( ((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))  )
#define ch(x,y,z)    ( ((x) & (y)) ^ ((~x) & (z)) )

// 32 steps of ACORN
// the last input parameter of this function is to indicate whether it is encryption (value1) or decryption (value 0).
void acorn128_32steps(uint8_t *state, uint8_t *plaintextbyte, uint8_t *ciphertextbyte, uint8_t cabyte, uint8_t cbbyte, uint8_t enc_dec_flag)
{
    uint8_t i;
    uint8_t j, f;
    uint8_t byte_12, byte_235, byte_244, byte_23,  byte_160, byte_111, byte_66, byte_196;
    uint8_t byte_230,byte_193, byte_154, byte_107, byte_61;
    uint8_t tem;
    uint8_t *state_tem, ksbyte;

    state_tem = state;

    for (i = 0; i < 4; i++)
    {
        byte_12  = (state_tem[1]  >> 4) | (state_tem[2]  << 4);
        byte_235 = (state_tem[29] >> 3) | (state_tem[30] << 5);
        byte_244 = (state_tem[30] >> 4) | (state_tem[31] << 4);
        byte_23  = (state_tem[2]  >> 7) | (state_tem[3]  << 1);
        byte_160 =  state_tem[20];
        byte_111 = (state_tem[13] >> 7) | (state_tem[14] << 1);
        byte_66  = (state_tem[8]  >> 2) | (state_tem[9]  << 6);
        byte_196 = (state_tem[24] >> 4) | (state_tem[25] << 4);

        byte_230 = (state_tem[28] >> 6) | (state_tem[29] << 2);
        byte_193 = (state_tem[24] >> 1) | (state_tem[25] << 7);
        byte_154 = (state_tem[19] >> 2) | (state_tem[20] << 6);
        byte_107 = (state_tem[13] >> 3) | (state_tem[14] << 5);
        byte_61  = (state_tem[7]  >> 5) | (state_tem[8]  << 3);

        tem = byte_235 ^ byte_230;
        state_tem[36] ^= tem << 1;
        state_tem[37] ^= tem >> 7;

        tem = byte_196 ^ byte_193;
        byte_230 ^= tem;
        state_tem[28] ^= tem << 6;
        state_tem[29] ^= tem >> 2;

        tem = byte_160 ^ byte_154;
        byte_193  ^= tem;
        state_tem[24] ^= tem << 1;
        state_tem[25] ^= tem >> 7;

        tem = byte_111 ^ byte_107;
        byte_154  ^= tem;
        state_tem[19] ^= tem << 2;
        state_tem[20] ^= tem >> 6;

        tem = byte_66 ^ byte_61;
        byte_107  ^= tem;
        state_tem[13] ^= tem << 3;
        state_tem[14] ^= tem >> 5;

        tem = byte_23 ^ state_tem[0];
        byte_61  ^= tem;
        state_tem[7] ^= tem << 5;
        state_tem[8] ^= tem >> 3;

        ksbyte = byte_12 ^ byte_154 ^ maj(byte_235, byte_61, byte_193) ^ ch(byte_230, byte_111, byte_66);

        if (enc_dec_flag == 1)
        {
            *(ciphertextbyte+i) = *(plaintextbyte + i) ^ ksbyte;
        }
        else
        {
            *(plaintextbyte+i) = *(ciphertextbyte + i) ^ ksbyte;
        }

        f = state_tem[0] ^ (~byte_107) ^ maj(byte_244, byte_23, byte_160) ^ (cabyte & byte_196) ^ (cbbyte & ksbyte);
        f ^= *(plaintextbyte + i);

        state_tem[36] ^= (f << 5);
        state_tem[37] ^= (f >> 3);

        state_tem++;
    }

    //shift by 32-bit positions
#if defined(AVR)
    for (j = 0; j <= 36; j++)
    {
        state[j] = state[j + 4];
    }
#else
    uint32_t *pp;
    pp = (uint32_t *)state;
    for (j = 0; j < 9; j++)
    {
        pp[j] = pp[j + 1];
    }
    state[36] = state[40];
#endif
    state[37] = 0;
    state[38] = 0;
    state[39] = 0;
    state[40] = 0;
}

// 8 steps of ACORN
// the last input parameter of this function is to indicate whether it is encryption (value1) or decryption (value 0).
void acorn128_8steps(uint8_t *state, uint8_t *plaintextbyte, uint8_t *ciphertextbyte, uint8_t cabyte, uint8_t cbbyte, uint8_t enc_dec_flag)
{
    uint8_t j, f;
    uint8_t byte_12, byte_235, byte_244, byte_23,  byte_160, byte_111, byte_66, byte_196;
    uint8_t byte_230,byte_193, byte_154, byte_107, byte_61;
    uint8_t tem, ksbyte;

    byte_12  = (state[1]  >> 4) | (state[2]  << 4);
    byte_235 = (state[29] >> 3) | (state[30] << 5);
    byte_244 = (state[30] >> 4) | (state[31] << 4);
    byte_23  = (state[2]  >> 7) | (state[3]  << 1);
    byte_160 =  state[20];
    byte_111 = (state[13] >> 7) | (state[14] << 1);
    byte_66  = (state[8]  >> 2) | (state[9]  << 6);
    byte_196 = (state[24] >> 4) | (state[25] << 4);

    byte_230 = (state[28] >> 6) | (state[29] << 2);
    byte_193 = (state[24] >> 1) | (state[25] << 7);
    byte_154 = (state[19] >> 2) | (state[20] << 6);
    byte_107 = (state[13] >> 3) | (state[14] << 5);
    byte_61  = (state[7]  >> 5) | (state[8]  << 3);

    tem = byte_235 ^ byte_230;
    state[36] ^= tem << 1;
    state[37] ^= tem >> 7;

    tem = byte_196 ^ byte_193;
    byte_230 ^= tem;
    state[28] ^= tem << 6;
    state[29] ^= tem >> 2;

    tem = byte_160 ^ byte_154;
    byte_193  ^= tem;
    state[24] ^= tem << 1;
    state[25] ^= tem >> 7;

    tem = byte_111 ^ byte_107;
    byte_154  ^= tem;
    state[19] ^= tem << 2;
    state[20] ^= tem >> 6;

    tem = byte_66 ^ byte_61;
    byte_107  ^= tem;
    state[13] ^= tem << 3;
    state[14] ^= tem >> 5;

    tem = byte_23 ^ state[0];
    byte_61  ^= tem;
    state[7] ^= tem << 5;
    state[8] ^= tem >> 3;

    ksbyte = byte_12 ^ byte_154 ^ maj(byte_235, byte_61, byte_193) ^ ch(byte_230, byte_111, byte_66);

    if (enc_dec_flag == 1)
    {
        *ciphertextbyte = *plaintextbyte ^ ksbyte;
    }
    else
    {
        *plaintextbyte = *ciphertextbyte ^ ksbyte;
    }

    f = state[0] ^ (~byte_107) ^ maj(byte_244, byte_23, byte_160) ^ (cabyte & byte_196) ^ (cbbyte & ksbyte);
    f ^= *plaintextbyte;

    //shift by 8-bit positions
    state[36] ^= (f << 5);
    state[37] ^= (f >> 3);
    for (j = 0; j <= 36; j++)
    {
        state[j] = state[j + 1];
    }
    state[37] = 0;
    state[38] = 0;
    state[39] = 0;
    state[40] = 0;
}

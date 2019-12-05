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
#include "padding.h"
#include "permute.h"


// the 256-step padding
// cb = 0xff for the padding after the associated data;
// cb = 0 for the padding after the plaintext.
void acorn128_fixed_padding_256(uint8_t *state, uint8_t cb)
{
    uint8_t i;
    uint8_t plaintextbyte[4];
    uint8_t ciphertextbyte[4];

    plaintextbyte[0] = 0x01;
    plaintextbyte[1] = 0x00;
    plaintextbyte[2] = 0x00;
    plaintextbyte[3] = 0x00;
    acorn128_8steps(state, plaintextbyte, ciphertextbyte, 0xff, cb, 1);

    plaintextbyte[0] = 0;
    for (i = 1; i < 4; i++)
    {
        acorn128_8steps(state, plaintextbyte, ciphertextbyte, 0xff, cb, 1);
    }

    for (i = 4; i < 128/8; i= i + 4)
    {
        acorn128_32steps(state, plaintextbyte, ciphertextbyte, 0xff, cb, 1);
    }

    for (i = 0; i < 128/8; i= i + 4)
    {
        acorn128_32steps(state, plaintextbyte, ciphertextbyte, 0x00, cb, 1);
    }
}

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

/* Reduced RAM usage in following implementation */
void acorn128_fixed_padding_256(uint8_t *state, uint8_t cb)
{
    uint8_t i;
    uint8_t plaintextbyte;
    uint8_t ciphertextbyte;

    plaintextbyte = 0x1;

    acorn128_8steps(state, &plaintextbyte, &ciphertextbyte, 0xff, cb, 1);

    plaintextbyte = 0;
    for (i = 1; i < 8; i++)
    {
        acorn128_8steps(state, &plaintextbyte, &ciphertextbyte, 0xff, cb, 1);
    }

    for (i = 8; i < 16; i=i+1)
    {
        acorn128_8steps(state, &plaintextbyte, &ciphertextbyte, 0xff, cb, 1);
    }

    for (i = 0; i < 16; i=i+1)
    {
        acorn128_8steps(state, &plaintextbyte, &ciphertextbyte, 0, cb, 1);
    }
}

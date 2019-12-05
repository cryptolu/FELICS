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
#include "cipher.h"
#include "permute.h"

void TagGeneration(uint8_t *state, uint8_t *tag)
{
    uint8_t plaintextbyte = 0;
    uint8_t ciphertextbyte;
    uint8_t i;

    for (i = 0; i < 80; i++)
    {
        acorn128_8steps(state, &plaintextbyte, &ciphertextbyte, 0xff, 0xff,1);
    }

    for (i = 0; i < 16; i++)
    {
        acorn128_8steps(state, &plaintextbyte, &ciphertextbyte, 0xff, 0xff,1);
        tag[i] = ciphertextbyte;
    }

}

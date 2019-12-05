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
#include <stdlib.h>

#include "cipher.h"
#include "constants.h"
#include "permute.h"
#include "padding.h"

void ProcessPlaintext(uint8_t *state, uint8_t *message, uint32_t message_length)
{

    uint32_t i;
    uint8_t ciphertextByte;

    for (i = 0; i < (message_length); i++)
    {
        acorn128_8steps(state, (message+i), &ciphertextByte, 0xff, 0,1);
        message[i]=ciphertextByte;
    }

    acorn128_fixed_padding_256(state, 0);

}

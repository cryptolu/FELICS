/*
 * SKINNY-64-128
 * @Time 2018
 * @Author luopeng(lo_robert@126.com)
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

#include "test_vectors.h"


/*
 *
 * Test vectors
 *
 */
/* Replace with the cipher test vectors */
//const uint8_t expectedPlaintext[BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03, 0xfc, 0xfd, 0xfe, 0xff};
//const uint8_t expectedKey[KEY_SIZE] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
//const uint8_t expectedCiphertext[BLOCK_SIZE] = {0x20, 0x0e, 0x15, 0xc8, 0x07, 0xea, 0x51, 0xdd};

const uint8_t expectedPlaintext[BLOCK_SIZE] = {0xcf, 0x16, 0xcf, 0xe8, 0xfd, 0x0f, 0x98, 0xaa};
const uint8_t expectedKey[KEY_SIZE] = {0x9e, 0xb9, 0x36, 0x40, 0xd0, 0x88, 0xda, 0x63, 0x76, 0xa3, 0x9d, 0x1c, 0x8b, 0xea, 0x71, 0xe1};
const uint8_t expectedCiphertext[BLOCK_SIZE] = {0x6c, 0xed, 0xa1, 0xf4, 0x3d, 0xe9, 0x2b, 0x9e};


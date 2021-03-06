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
//const uint8_t expectedPlaintext[BLOCK_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//const uint8_t expectedKey[KEY_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//const uint8_t expectedCiphertext[BLOCK_SIZE] = {0x18, 0x7b, 0xb7, 0x26, 0xeb, 0xed, 0x12, 0x73};

//const uint8_t expectedPlaintext[BLOCK_SIZE] = {0x18, 0x7b, 0xb7, 0x26, 0xeb, 0xed, 0x12, 0x73};
//const uint8_t expectedKey[KEY_SIZE] = {0x71, 0x24, 0x1e, 0x50, 0xaf, 0x3a, 0xe3, 0xb8, 0xb8, 0xec, 0x6c, 0x40, 0x7d, 0x4a, 0xb8, 0x08};
//const uint8_t expectedCiphertext[BLOCK_SIZE] = {0xb4, 0x4c, 0x56, 0x57, 0x7f, 0x03, 0xf9, 0x64};

//const uint8_t expectedPlaintext[BLOCK_SIZE] = {0xb4, 0x4c, 0x56, 0x57, 0x7f, 0x03, 0xf9, 0x64};
//const uint8_t expectedKey[KEY_SIZE] = {0xae, 0x66, 0xf2, 0x78, 0x1f, 0x18, 0x9c, 0xf4, 0x75, 0x6c, 0x40, 0x58, 0x30, 0x42, 0x1f, 0x54};
//const uint8_t expectedCiphertext[BLOCK_SIZE] = {0x80, 0x63, 0xf2, 0xeb, 0xf7, 0xb6, 0x6b, 0x32};

//const uint8_t expectedPlaintext[BLOCK_SIZE] = {0x80, 0x63, 0xf2, 0xeb, 0xf7, 0xb6, 0x6b, 0x32};
//const uint8_t expectedKey[KEY_SIZE] = {0xc2, 0x7e, 0x5d, 0x20, 0x9b, 0xc2, 0x9e, 0x50, 0x11, 0x32, 0x27, 0x74, 0xc2, 0xd6, 0x91, 0xe0};
//const uint8_t expectedCiphertext[BLOCK_SIZE] = {0x53, 0xa1, 0xbd, 0x35, 0x7d, 0x89, 0x64, 0x22};

const uint8_t expectedPlaintext[BLOCK_SIZE] = {0x53, 0xa1, 0xbd, 0x35, 0x7d, 0x89, 0x64, 0x22};
const uint8_t expectedKey[KEY_SIZE] = {0xe7, 0x3d, 0x9c, 0x57, 0xbe, 0x33, 0x0f, 0xb3, 0x96, 0x27, 0xce, 0x23, 0x8d, 0xa7, 0x09, 0x33};
const uint8_t expectedCiphertext[BLOCK_SIZE] = {0x48, 0x23, 0xca, 0x33, 0x9d, 0x16, 0x55, 0x77};

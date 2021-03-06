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
//const uint8_t expectedKey[KEY_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//const uint8_t expectedIV[IV_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//const uint8_t expectedPlaintext[TEST_STREAM_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//const uint8_t expectedCiphertext[TEST_STREAM_SIZE] = {0xfb, 0xe0, 0xbf, 0x26, 0x58, 0x59, 0x05, 0x1b, 0x51, 0x7a, 0x2e, 0x4e, 0x23, 0x9f, 0xc9, 0x7f};

//const uint8_t expectedKey[KEY_SIZE] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
//const uint8_t expectedIV[IV_SIZE] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
//const uint8_t expectedPlaintext[TEST_STREAM_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//const uint8_t expectedCiphertext[TEST_STREAM_SIZE] = {0xee, 0xae, 0x21, 0x19, 0x49, 0x94, 0x7b, 0x1a, 0xd8, 0x26, 0x7f, 0xdf, 0xd7, 0x46, 0x78, 0x18};

//const uint8_t expectedKey[KEY_SIZE] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
//const uint8_t expectedIV[IV_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//const uint8_t expectedPlaintext[TEST_STREAM_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//const uint8_t expectedCiphertext[TEST_STREAM_SIZE] = {0xdd, 0xa5, 0xbe, 0x0d, 0x7a, 0xcf, 0x12, 0x39, 0x8c, 0x4c, 0x08, 0x23, 0xc7, 0x93, 0xa0, 0x6b};

//const uint8_t expectedKey[KEY_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//const uint8_t expectedIV[IV_SIZE] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
//const uint8_t expectedPlaintext[TEST_STREAM_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//const uint8_t expectedCiphertext[TEST_STREAM_SIZE] = {0x14, 0xce, 0xc4, 0x28, 0x68, 0x16, 0x46, 0xee, 0x59, 0x8f, 0xda, 0x31, 0x2e, 0x8b, 0xcb, 0x36};

//const uint8_t expectedKey[KEY_SIZE] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
//const uint8_t expectedIV[IV_SIZE] = {0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
//const uint8_t expectedPlaintext[TEST_STREAM_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//const uint8_t expectedCiphertext[TEST_STREAM_SIZE] = {0x20, 0xdf, 0x66, 0xd9, 0x63, 0x97, 0x50, 0x49, 0x8a, 0xaa, 0x40, 0xb1, 0x2e, 0xde, 0x86, 0xdd};

const uint8_t expectedKey[KEY_SIZE] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
const uint8_t expectedIV[IV_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23};
const uint8_t expectedPlaintext[TEST_STREAM_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t expectedCiphertext[TEST_STREAM_SIZE] = {0x45, 0x50, 0x9d, 0xd9, 0xfe, 0x19, 0xc7, 0x5f, 0x22, 0x66, 0xef, 0x51, 0xd9, 0x7e, 0x17, 0xaa};

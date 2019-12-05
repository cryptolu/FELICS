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
//const uint8_t expectedPlaintext[BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
//const uint8_t expectedKey[KEY_SIZE] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
//const uint8_t expectedCiphertext[BLOCK_SIZE] = {0x5f, 0x9f, 0x3f, 0xc4, 0xb9, 0xd8, 0x43, 0x61, 0xba, 0x11, 0xc1, 0xa4, 0x03, 0xbc, 0xc0, 0xe4};

const uint8_t expectedKey[KEY_SIZE] = {0x4f, 0x55, 0xcf, 0xb0, 0x52, 0x0c, 0xac, 0x52, 0xfd, 0x92, 0xc1, 0x5f, 0x37, 0x07, 0x3e, 0x93,};
const uint8_t expectedPlaintext[BLOCK_SIZE] = {0xf2, 0x0a, 0xdb, 0x0e, 0xb0, 0x8b, 0x64, 0x8a, 0x3b, 0x2e, 0xee, 0xd1, 0xf0, 0xad, 0xda, 0x14,};
const uint8_t expectedCiphertext[BLOCK_SIZE] = {0x22, 0xff, 0x30, 0xd4, 0x98, 0xea, 0x62, 0xd7, 0xe4, 0x5b, 0x47, 0x6e, 0x33, 0x67, 0x5b, 0x74,};

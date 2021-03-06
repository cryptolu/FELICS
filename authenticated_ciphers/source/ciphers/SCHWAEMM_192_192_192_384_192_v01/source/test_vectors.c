/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2017 University of Luxembourg
 *
 * Written in 2019 by Luan Cardoso dos Santos <luan.cardoso@uni.lu> <luancardoso@icloud.com>
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

const uint8_t expectedKey[KEY_SIZE] =
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
          0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
          0x16, 0x17};
ALIGNED const uint8_t expectedNonce[NONCE_SIZE] =
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
          0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
          0x16, 0x17};
ALIGNED const uint8_t expectedAssociatedData[TEST_ASSOCIATED_DATA_SIZE] =
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
          0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
          0x16, 0x17};

const uint8_t expectedCiphertext[TEST_MESSAGE_SIZE] =
        { 0xC8, 0x9D, 0x91, 0xA6, 0x5A, 0xC4, 0x1A, 0xCF, 0xB5, 0x76, 0x4B,
          0x4A, 0x3D, 0xEA, 0x34, 0xE5, 0x22, 0xA2, 0x57, 0xFB, 0x8E, 0xF7,
          0xD5, 0xA6};
const uint8_t expectedPlaintext[TEST_MESSAGE_SIZE] =
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
          0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
          0x16, 0x17};
const uint8_t expectedTag[TAG_SIZE] =
        { 0x4E, 0x0C, 0xF4, 0xA6, 0x14, 0x9A, 0x64, 0x0E, 0x3F, 0x2F, 0x42,
          0x90, 0x73, 0xD4, 0xA4, 0xB6, 0x6A, 0xA0, 0x6A, 0x76, 0x72, 0x6A,
          0x3F, 0xB4};


const uint8_t expectedPostInitializationState[STATE_SIZE] =
        { 0x5b, 0x65, 0xb5, 0x97, 0xb5, 0x1d, 0x35, 0x09, 0xa6, 0x39, 0x43,
          0x71, 0x39, 0xd2, 0x5d, 0xce, 0x3c, 0x51, 0x85, 0xe4, 0x4b, 0xb8,
          0xf4, 0x2b, 0x94, 0xfb, 0xbc, 0xf3, 0x72, 0xbd, 0x09, 0xa3, 0xc2,
          0xe0, 0x08, 0xd7, 0x5a, 0x3d, 0xac, 0xb8, 0xa8, 0xb6, 0x30, 0x91,
          0xb1, 0x75, 0x37, 0x3b };
const uint8_t expectedPostAssociatedDataProcessingState[STATE_SIZE] =
        { 0xc8, 0x9c, 0x93, 0xa5, 0x5e, 0xc1, 0x1c, 0xc8, 0xbd, 0x7f, 0x41,
          0x41, 0x31, 0xe7, 0x3a, 0xea, 0x32, 0xb3, 0x45, 0xe8, 0x9a, 0xe2,
          0xc3, 0xb1, 0x4e, 0x5b, 0x90, 0x79, 0x19, 0x3b, 0x73, 0x30, 0x56,
          0xc6, 0x90, 0x66, 0xde, 0xe7, 0x26, 0x7b, 0x97, 0xc9, 0x85, 0x36,
          0xd6, 0x9c, 0xc3, 0x45 };
const uint8_t expectedPostPlaintextProcessingState[STATE_SIZE] =
        { 0x2b, 0x16, 0x6f, 0x53, 0xc0, 0xb5, 0x9c, 0xa7, 0x87, 0x2c, 0xbc,
          0xbc, 0x65, 0xef, 0xfc, 0x33, 0x6d, 0xac, 0xad, 0xdf, 0xb6, 0xa4,
          0x9c, 0x31, 0x4e, 0x0d, 0xf6, 0xa5, 0x10, 0x9f, 0x62, 0x09, 0x37,
          0x26, 0x48, 0x9b, 0x7f, 0xd9, 0xaa, 0xb9, 0x7a, 0xb1, 0x78, 0x65,
          0x66, 0x7f, 0x29, 0xa3 };
const uint8_t expectedPostFinalizationState[STATE_SIZE] =
        { 0x2b, 0x16, 0x6f, 0x53, 0xc0, 0xb5, 0x9c, 0xa7, 0x87, 0x2c, 0xbc,
          0xbc, 0x65, 0xef, 0xfc, 0x33, 0x6d, 0xac, 0xad, 0xdf, 0xb6, 0xa4,
          0x9c, 0x31, 0x4e, 0x0c, 0xf4, 0xa6, 0x14, 0x9a, 0x64, 0x0e, 0x3f,
          0x2f, 0x42, 0x90, 0x73, 0xd4, 0xa4, 0xb6, 0x6a, 0xa0, 0x6a, 0x76,
          0x72, 0x6a, 0x3f, 0xb4 };

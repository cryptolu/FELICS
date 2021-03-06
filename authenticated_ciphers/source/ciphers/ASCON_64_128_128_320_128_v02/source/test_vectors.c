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

#include "test_vectors.h"

#define TEST 0

#if (TEST == 0)
/* Input set for normal testing */
const uint8_t expectedKey[KEY_SIZE] =
        { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
    0xbb, 0xcc, 0xdd, 0xee, 0xff
};
const uint8_t expectedNonce[NONCE_SIZE] =
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00
};
const uint8_t expectedAssociatedData[TEST_ASSOCIATED_DATA_SIZE] =
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

const uint8_t expectedCiphertext[TEST_MESSAGE_SIZE] =
        { 0x45, 0xb3, 0xac, 0xd2, 0x5b, 0xb5, 0xd7, 0xe4 };
const uint8_t expectedPlaintext[TEST_MESSAGE_SIZE] =
        { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
const uint8_t expectedTag[TAG_SIZE] =
        { 0xe2, 0xb5, 0x86, 0xc1, 0xa6, 0x2c, 0xab, 0xfc, 0x41, 0x80, 0xc2,
    0x34, 0xb8, 0x16, 0x94, 0x15
};

const uint8_t expectedPostInitializationState[STATE_SIZE] =
        { 0xf0, 0x2d, 0xaa, 0xb9, 0xf5, 0x09, 0x89, 0x43,
    0x81, 0x30, 0x08, 0x06, 0xb3, 0xbd, 0x0d, 0x43,
    0x6a, 0x38, 0x03, 0xd0, 0xf5, 0xb6, 0x34, 0x70,
    0x70, 0xb4, 0x51, 0xbd, 0x23, 0xf3, 0xbc, 0xb5,
    0x90, 0x26, 0x7c, 0x7e, 0xfb, 0x41, 0x58, 0x62
};
const uint8_t expectedPostAssociatedDataProcessingState[STATE_SIZE] =
        { 0x33, 0x93, 0xec, 0x08, 0x41, 0xc6, 0x97, 0xa4,
    0x01, 0x7f, 0x1f, 0xac, 0xa7, 0x3d, 0x77, 0x46,
    0x23, 0xc0, 0xba, 0x11, 0x1f, 0x42, 0xb2, 0xb1,
    0x5c, 0x2b, 0x3a, 0xbc, 0x39, 0x49, 0x69, 0x66,
    0xa3, 0xff, 0xf0, 0x80, 0x95, 0xa2, 0x2f, 0x1d
};
const uint8_t expectedPostPlaintextProcessingState[STATE_SIZE] =
        { 0x4f, 0xb1, 0x66, 0x1a, 0x67, 0x55, 0x58, 0xb5,
    0x32, 0x7a, 0xe3, 0xd6, 0xf1, 0x4d, 0xcd, 0xe7,
    0xf1, 0x7a, 0x66, 0x0b, 0x0d, 0x2c, 0x6e, 0x16,
    0x79, 0x6a, 0xc1, 0x58, 0xbe, 0x1d, 0x45, 0x3b,
    0x9c, 0x54, 0x7a, 0xbf, 0x29, 0x0d, 0x5d, 0x31
};
const uint8_t expectedPostFinalizationState[STATE_SIZE] =
        { 0xcf, 0x09, 0xdc, 0x23, 0xc0, 0x08, 0x10, 0x01,
    0xdc, 0x95, 0x94, 0x22, 0x4f, 0xa8, 0x95, 0x8b,
    0xb7, 0xde, 0xb3, 0xf4, 0x3d, 0x0f, 0x08, 0xec,
    0xfe, 0xd6, 0x98, 0xdc, 0x1e, 0x22, 0x29, 0x87,
    0x80, 0xe1, 0x94, 0x08, 0x67, 0x46, 0x86, 0x90
};

#elif (TEST == 1)
/* Input set for padding testing */
const uint8_t expectedKey[KEY_SIZE] =
        { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
    0xbb, 0xcc, 0xdd, 0xee, 0xff
};
ALIGNED const uint8_t expectedNonce[NONCE_SIZE] =
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00
};
ALIGNED const uint8_t expectedAssociatedData[TEST_ASSOCIATED_DATA_SIZE] =
        { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };

const uint8_t expectedCiphertext[TEST_MESSAGE_SIZE] =
        { 0x08, 0x2d, 0xa9, 0x64, 0x56, 0xa4, 0xa3, 0xe0, 0x4d, 0xb2, 0x3d,
    0x71, 0x6c, 0x3e, 0x01, 0xfc, 0xb4
};
const uint8_t expectedPlaintext[TEST_MESSAGE_SIZE] =
        { 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07,
    0x06, 0x05, 0x04, 0x03, 0x02, 0x01
};
const uint8_t expectedTag[TAG_SIZE] =
        { 0x97, 0x97, 0xfb, 0xb1, 0x40, 0x28, 0xb8, 0x3a, 0x40, 0x2a, 0xde,
    0x41, 0x7a, 0x68, 0xaa, 0x4d
};

const uint8_t expectedPostInitializationState[STATE_SIZE] =
        { 0xf0, 0x2d, 0xaa, 0xb9, 0xf5, 0x09, 0x89, 0x43,
    0x81, 0x30, 0x08, 0x06, 0xb3, 0xbd, 0x0d, 0x43,
    0x6a, 0x38, 0x03, 0xd0, 0xf5, 0xb6, 0x34, 0x70,
    0x70, 0xb4, 0x51, 0xbd, 0x23, 0xf3, 0xbc, 0xb5,
    0x90, 0x26, 0x7c, 0x7e, 0xfb, 0x41, 0x58, 0x62
};
const uint8_t expectedPostAssociatedDataProcessingState[STATE_SIZE] =
        { 0x25, 0xa6, 0xa1, 0x10, 0x2f, 0xa5, 0x4a, 0x52,
    0x91, 0x46, 0x02, 0x1d, 0xcc, 0x01, 0xc4, 0xe9,
    0xa9, 0x9f, 0x73, 0x7f, 0x5b, 0x57, 0x35, 0x9b,
    0xff, 0x71, 0xb2, 0xaf, 0xdb, 0x8c, 0x3a, 0xf6,
    0xd0, 0x9a, 0x0c, 0x59, 0x55, 0xf7, 0x47, 0xa9
};
const uint8_t expectedPostPlaintextProcessingState[STATE_SIZE] =
        { 0xff, 0xca, 0xc2, 0xa7, 0x96, 0x2d, 0xef, 0xe8,
    0x63, 0xb5, 0x0b, 0x1e, 0x3b, 0x30, 0x8c, 0x41,
    0x6a, 0xb8, 0xa9, 0x06, 0xa3, 0x75, 0xa1, 0x5a,
    0xb4, 0x26, 0x8e, 0x01, 0x4c, 0x1e, 0x5d, 0xc8,
    0xf1, 0x64, 0x1c, 0xff, 0xf3, 0x25, 0xbc, 0xc7
};
const uint8_t expectedPostFinalizationState[STATE_SIZE] =
        { 0x5f, 0x61, 0x63, 0xc4, 0x4d, 0x31, 0x61, 0xce,
    0x84, 0x93, 0xed, 0x3b, 0x08, 0xf9, 0x7b, 0x3d,
    0x01, 0xca, 0x79, 0x9d, 0xc0, 0x05, 0x94, 0x7d,
    0x21, 0xad, 0x13, 0x95, 0x88, 0xf0, 0xee, 0xd0,
    0x9a, 0x4b, 0x3c, 0x11, 0xf5, 0x37, 0x19, 0xaa
};

#endif

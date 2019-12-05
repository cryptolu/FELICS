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


/*
 *
 * Test vectors
 *
 */
/* Replace with the cipher test vectors */
const uint8_t expectedKey[KEY_SIZE] = {};
ALIGNED const uint8_t expectedNonce[NONCE_SIZE] = {};
ALIGNED const uint8_t expectedAssociatedData[TEST_ASSOCIATED_DATA_SIZE] = {};

const uint8_t expectedCiphertext[TEST_MESSAGE_SIZE] = {};
const uint8_t expectedPlaintext[TEST_MESSAGE_SIZE] = {};
const uint8_t expectedTag[TAG_SIZE] = {};

const uint8_t expectedPostInitializationState[STATE_SIZE] = {};
const uint8_t expectedPostAssociatedDataProcessingState[STATE_SIZE] = {};
const uint8_t expectedPostPlaintextProcessingState[STATE_SIZE] = {};
const uint8_t expectedPostFinalizationState[STATE_SIZE] = {};

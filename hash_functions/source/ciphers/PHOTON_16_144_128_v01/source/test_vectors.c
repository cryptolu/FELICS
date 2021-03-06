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
/*
 *
 * Test vectors
 *
 */
#if(TEST == 0)
/* Test vectors for normal testing */
const uint8_t expectedMessage[TEST_MESSAGE_SIZE] = {0x11, 0x22}; /* Initial message value */
const uint8_t expectedDigest[DIGEST_SIZE] = {0xb2, 0x39, 0x75, 0x68, 0xe1, 0xe3, 0xe1, 0x27, 0x9a, 0x1b, 0xbe, 0x8f, 0xd7, 0x5d, 0xac, 0x5a}; /* Digest value after finalization */

/* Expected state values */

const uint8_t expectedPostInitializationState[STATE_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00}; /* State value after initialization */
const uint8_t expectedPostUpdateState[STATE_SIZE] = {0x06, 0x02, 0x07, 0x0c, 0x09, 0x0c, 0x09, 0x04, 0x09, 0x00, 0x06, 0x04, 0x03, 0x04, 0x0f, 0x0f, 0x0c, 0x0e, 0x03, 0x07, 0x0e, 0x02, 0x06, 0x0a, 0x03, 0x0a, 0x04, 0x01, 0x04, 0x01, 0x0b, 0x0f, 0x07, 0x0c, 0x0c, 0x0d}; /* State value after Update */
const uint8_t expectedPostFinalizationState[STATE_SIZE] = {0x0a, 0x0c, 0x05, 0x0a, 0x0e, 0x08, 0x06, 0x00, 0x06, 0x04, 0x01, 0x06, 0x07, 0x0c, 0x0d, 0x05, 0x04, 0x04, 0x00, 0x08, 0x0c, 0x0b, 0x0b, 0x0f, 0x01, 0x05, 0x09, 0x0c, 0x06, 0x01, 0x07, 0x03, 0x05, 0x04, 0x03, 0x0a, 0x00, 0x00, 0x00}; /* State value after finalization */

#elif(TEST == 1)
/* Test vectors for normal testing */
const uint8_t expectedMessage[TEST_MESSAGE_SIZE] = {0xab}; /* Initial message value */
const uint8_t expectedDigest[DIGEST_SIZE] = {0xc9, 0xd6, 0x55, 0x87, 0xab, 0xc0, 0x82, 0x42, 0xfe, 0x10, 0x7c, 0x1f, 0xa0, 0x1f, 0x70, 0xaa}; /* Digest value after finalization */

/* Expected state values */

const uint8_t expectedPostInitializationState[STATE_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00}; /* State value after initialization */
const uint8_t expectedPostUpdateState[STATE_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0xab, 0x00, 0x01}; /* State value after Update */
const uint8_t expectedPostFinalizationState[STATE_SIZE] = {0x07, 0x00, 0x0a, 0x0a, 0x0e, 0x08, 0x0c, 0x05, 0x05, 0x0f, 0x06, 0x02, 0x01, 0x02, 0x0d, 0x05, 0x02, 0x08, 0x0f, 0x00, 0x03, 0x07, 0x09, 0x00, 0x09, 0x0e, 0x0a, 0x0e, 0x09, 0x0f, 0x03, 0x04, 0x08, 0x03, 0x0c, 0x06}; /* State value after finalization */

#endif

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

/* Replace with the hash test vectors */
const uint8_t expectedMessage[TEST_MESSAGE_SIZE] = {0x11}; /* Initial message value */
const uint8_t expectedDigest[DIGEST_SIZE] = {0x47, 0x7c, 0xdd, 0x9e, 0x6d, 0xca, 0x7a, 0x9f, 0x31, 0xc1, 0x3c, 0x73, 0x42, 0x1f, 0x83, 0x63, 0x35}; /* Digest value after finalization */

/* Expected state values */

const uint8_t expectedPostInitializationState[STATE_SIZE] = {0xd8,0xda,0xca,0x44,0x41,0x4a,0x09,0x97,0x19,0xc8,0x0a,0xa3,0xaf,0x06,0x56,0x44,0xdb}; /* State value after initialization */
const uint8_t expectedPostUpdateState[STATE_SIZE] = {0x51, 0x35, 0x6f, 0x51, 0x96, 0xc9, 0x33, 0xb6, 0x98, 0xde, 0x02, 0xee, 0xd5, 0xff, 0x04, 0xed, 0x47}; /* State value after Update */
const uint8_t expectedPostFinalizationState[STATE_SIZE] = {0x14, 0x32, 0x3d, 0x9e, 0x08, 0x07, 0xa5, 0xc7, 0x07, 0xb4, 0xf5, 0x17, 0x99, 0x24, 0x42, 0x86, 0x35}; /* State value after finalization */
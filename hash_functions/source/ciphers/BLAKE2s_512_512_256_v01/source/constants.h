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

#ifndef CONSTANTS_H
#define CONSTANTS_H

#include "data_types.h"
/*
 *
 * Cipher characteristics:
 *  BLOCK_SIZE - the hash block size in bytes
 *  STATE_SIZE - the hash state size
 *  DIGEST_SIZE - the hash digest size
 *  NO_OF_ROUNDS - number of rounds in compression phase of the hash
 *  SPONG - Boolean indicating mode of the hash compression round
 *
 */

#define DIGEST_SIZE 32 /* Replace with hash digest size */
#define BLOCK_SIZE 64 /* Replace with hash block size */
#define STATE_SIZE 131 /* Replace with hash state size */
#define NO_OF_ROUNDS 10 /* Replace with number of rounds in hash compression */

#define TEST_MESSAGE_SIZE BLOCK_SIZE

#define SPONGE FALSE

#define BLAKE2S_KEYBYTES 32
#define BLAKE2S_SALTBYTES 8
#define BLAKE2S_PERSONALBYTES 8

extern const uint8_t blake2s_sigma[10][16];
extern const uint32_t blake2s_IV[8];
#endif

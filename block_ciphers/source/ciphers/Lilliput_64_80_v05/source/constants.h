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

#ifndef CONSTANTS_H
#define CONSTANTS_H

#include "data_types.h"


/*
 *
 * Cipher characteristics:
 * 	BLOCK_SIZE - the cipher block size in bytes
 * 	KEY_SIZE - the cipher key size in bytes
 *	ROUND_KEY_SIZE - the cipher round keys size in bytes
 * 	NUMBER_OF_ROUNDS - the cipher number of rounds
 *
 */
#define BLOCK_SIZE 16 

#define KEY_SIZE 20
#define ROUND_KEYS_SIZE 240

#define NUMBER_OF_ROUNDS 30


/*
 *
 * Cipher constants
 *
 */
/* Replace with the cipher constants declaration */


extern SBOX_BYTE S[16];

extern SBOX_BYTE Tabi6[30];

extern SBOX_BYTE Tabi7[30];

extern SBOX_BYTE Sconcat1[2][2][2][2];

extern SBOX_BYTE Sconcat2[3][3][3][3];

extern SBOX_BYTE Sconcat4[5][5][5][5];

extern SBOX_BYTE Sconcat8[9][9][9][9];


#endif /* CONSTANTS_H */

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
 *  BLOCK_SIZE - the cipher block size in bytes
 *  KEY_SIZE - the cipher key size in bytes
 *  ROUND_KEY_SIZE - the cipher round keys size in bytes
 *  NUMBER_OF_ROUNDS - the cipher number of rounds
 *
 */
#define BLOCK_SIZE 16 /* Replace with the cipher block size in bytes */

#define KEY_SIZE 16 /* Replace with the cipher key size in bytes */
#define ROUND_KEYS_SIZE 320 /* Replace with the cipher round keys size in bytes */

#define NUMBER_OF_ROUNDS 40 /* Replace with the cipher number of rounds */


/*
 *
 * Cipher constants
 *
 */
/* Replace with the cipher constants declaration */
#ifndef PC
    extern RAM_DATA_BYTE     SBOX[];
    extern RAM_DATA_BYTE INV_SBOX[];
    extern RAM_DATA_BYTE RC[];
    extern RAM_DATA_BYTE TWEAKEY_P[];
    extern RAM_DATA_BYTE TWEAKEY_P_inv[];

#else

    extern int ver;
    extern int versions[6][3];

    extern RAM_DATA_BYTE sbox_4[];
    extern RAM_DATA_BYTE sbox_4_inv[];

    /*  8-bit Sbox */
    extern RAM_DATA_BYTE sbox_8[];
    extern RAM_DATA_BYTE sbox_8_inv[];
    /*  ShiftAndSwitchRows permutation */
    extern RAM_DATA_BYTE P[];
    extern RAM_DATA_BYTE P_inv[];

    /*  Tweakey permutation */
    extern RAM_DATA_BYTE TWEAKEY_P[];
    extern RAM_DATA_BYTE TWEAKEY_P_inv[];

    /*  round constants */
    extern RAM_DATA_BYTE RC[];
#endif /* PC */

#endif /* CONSTANTS_H */

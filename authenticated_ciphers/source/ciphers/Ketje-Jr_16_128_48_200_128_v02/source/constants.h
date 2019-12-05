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
 *  BLOCK_SIZE - the cipher block size in bytes
 *  KEY_SIZE - the cipher key size in bytes
 *  NONCE_SIZE - the cipher nonce size in bytes
 *  STATE_SIZE - the cipher state size
 *  TAG_SIZE - cipher tag size
 *
 */
#define BLOCK_SIZE 2            /* Replace with cipher block size */
#define KEY_SIZE 16             /* Replace with cipher key size */
#define NONCE_SIZE 6            /* Replace with cipher nonce size */
#define STATE_SIZE 25           /* Replace with cipher state size */
#define TAG_SIZE 16             /* Replace with cipher tag size */


#define TEST_MESSAGE_SIZE 7
#define TEST_ASSOCIATED_DATA_SIZE 6

/*  Ketje rounds */
#define Ket_StartRounds     12
#define Ket_StepRounds      1
#define Ket_StrideRounds    6

#define maxNrRounds 18
#define nrLanes 25
#define Ketje_LaneSize 1

#define FRAMEBITSEMPTY  0x01
#define FRAMEBITS0      0x02
#define FRAMEBITS00     0x04
#define FRAMEBITS10     0x05
#define FRAMEBITS01     0x06
#define FRAMEBITS11     0x07

extern KETJE_CONST_BYTE KeccakRoundConstants[maxNrRounds];
extern KETJE_CONST_BYTE KeccakRhoOffsets[nrLanes];
extern KETJE_CONST_BYTE KetJr_StateTwistIndexes[];

#endif

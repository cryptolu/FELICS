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

#ifndef __PHOTON_H_
#define __PHOTON_H_

#include <stdint.h>
#include "constants.h"

#define min(x,y) ((x)<(y)?(x):(y))
#define max(x,y) ((x)>(y)?(x):(y))
#define WORDFILTER (((uint8_t) 1<<CELL_SIZE)-1)

void PrintState(uint8_t state[MATRIX_SIZE][MATRIX_SIZE]);

uint8_t FieldMult(uint8_t a, uint8_t b);

void AddKey(uint8_t state[MATRIX_SIZE][MATRIX_SIZE], uint8_t round);

void SubCell(uint8_t state[MATRIX_SIZE][MATRIX_SIZE]);

void ShiftRow(uint8_t state[MATRIX_SIZE][MATRIX_SIZE]);

void MixColumn(uint8_t state[MATRIX_SIZE][MATRIX_SIZE]);

void Permutation(uint8_t state[MATRIX_SIZE][MATRIX_SIZE]);

uint8_t GetByte(const uint8_t *message, uint8_t BitOffSet, uint8_t NoOfBits);

void WordXorByte(uint8_t state[MATRIX_SIZE][MATRIX_SIZE], const uint8_t *message, uint8_t BitOffSet, uint8_t WordOffSet, uint8_t NoOfBits);

void WriteByte(uint8_t *message, uint8_t value, uint8_t BitOffSet, uint8_t NoOfBits);

void WordToByte(uint8_t state[MATRIX_SIZE][MATRIX_SIZE], uint8_t *message, uint8_t BitOffSet, uint8_t NoOfBits);

void PermutationOnByte(uint8_t* in);

#endif /* __PHOTON_H_ */

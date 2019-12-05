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
 * FELICS is free software; you can redimessageibute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is dimessageibuted in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "constants.h"
#include "util.h"

const uint8_t ReductionPoly = 0x3;

uint8_t FieldMult(uint8_t a, uint8_t b)
{
	uint8_t x = a, ret = 0;
	uint8_t i;
	for(i = 0; i < CELL_SIZE; i++) {
		if((b>>i)&1) ret ^= x;
		if((x>>(CELL_SIZE-1))&1) {
			x <<= 1;
			x ^= ReductionPoly;
		}
		else x <<= 1;
	}
	return ret&WORDFILTER;
}

void AddKey(uint8_t state[MATRIX_SIZE][MATRIX_SIZE], uint8_t round)
{
	uint8_t i;
	for(i = 0; i < MATRIX_SIZE; i++)
		state[i][0] ^= RC[i][round];
}

void SubCell(uint8_t state[MATRIX_SIZE][MATRIX_SIZE])
{
	uint8_t i,j;
	for(i = 0; i < MATRIX_SIZE; i++)
		for(j = 0; j <  MATRIX_SIZE; j++)
			state[i][j] = SBox[state[i][j]];
}

void ShiftRow(uint8_t state[MATRIX_SIZE][MATRIX_SIZE])
{
	uint8_t i, j;
	uint8_t tmp[MATRIX_SIZE];
	for(i = 1; i < MATRIX_SIZE; i++) {
		for(j = 0; j < MATRIX_SIZE; j++)
			tmp[j] = state[i][j];
		for(j = 0; j < MATRIX_SIZE; j++)
			state[i][j] = tmp[(j+i)%MATRIX_SIZE];
	}
}

void MixColumn(uint8_t state[MATRIX_SIZE][MATRIX_SIZE])
{
	uint8_t i, j, k;
	uint8_t tmp[MATRIX_SIZE];
	for(j = 0; j < MATRIX_SIZE; j++){
		for(i = 0; i < MATRIX_SIZE; i++) {
			uint8_t sum = 0;
			for(k = 0; k < MATRIX_SIZE; k++)
				sum ^= FieldMult(MixColMatrix[i][k], state[k][j]);
			tmp[i] = sum;
        }
        for(i = 0; i < MATRIX_SIZE; i++)
            state[i][j] = tmp[i];
	}
}

void Permutation(uint8_t state[MATRIX_SIZE][MATRIX_SIZE])
{
    uint8_t i;
    for(i = 0; i < NO_OF_ROUNDS; i++) {
        //if(DEBUG) printf("--- Round %d ---\n", i);
        AddKey(state, i);
        SubCell(state);
        ShiftRow(state);
        MixColumn(state); 
	}
}
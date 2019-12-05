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

/* get NoOfBits bits values from message starting from BitOffSet-th bit 
 * Requirement: NoOfBits <= 8 */
uint8_t GetByte(const uint8_t *message, uint8_t BitOffSet, uint8_t NoOfBits)
{
    return (message[BitOffSet>>3] >> (4-(BitOffSet&0x4))) & WORDFILTER;
}

void WordXorByte(uint8_t state[MATRIX_SIZE][MATRIX_SIZE], const uint8_t *message, uint8_t BitOffSet, uint8_t WordOffSet, uint8_t NoOfBits)
{
	uint8_t i = 0;
	while(i < NoOfBits)
	{
		state[(WordOffSet+(i/CELL_SIZE))/MATRIX_SIZE][(WordOffSet+(i/CELL_SIZE))%MATRIX_SIZE] ^= GetByte(message, BitOffSet+i, min(CELL_SIZE, NoOfBits-i)) << (CELL_SIZE-min(CELL_SIZE,NoOfBits-i));
		i += CELL_SIZE;
	}
}
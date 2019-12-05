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

/* ensure NoOfBits <=8 */
void WriteByte(uint8_t *message, uint8_t value, uint8_t BitOffSet, uint8_t NoOfBits)
{
	
    uint8_t ByteIndex = BitOffSet >> 3;
    uint8_t BitIndex = BitOffSet & 0x7;
    uint8_t localFilter = (((uint8_t)1)<<NoOfBits) - 1;
    value &= localFilter;
    if(BitIndex+ NoOfBits <= 8) {
        message[ByteIndex] &= ~(localFilter<<(8-BitIndex-NoOfBits));
        message[ByteIndex] |= value<<(8-BitIndex-NoOfBits);
    }
    else
    {
        uint32_t tmp = ((((uint32_t) message[ByteIndex])<<8)&0xFF00) | (((uint32_t) message[ByteIndex+1])&0xFF);
        tmp &= ~((((uint32_t)localFilter)&0xFF)<<(16-BitIndex-NoOfBits));
        tmp |= (((uint32_t)(value))&0xFF)<<(16-BitIndex-NoOfBits);
        message[ByteIndex] = (tmp>>8)&0xFF;
        message[ByteIndex+1] = tmp&0xFF;
    }
}

void WordToByte(uint8_t state[MATRIX_SIZE][MATRIX_SIZE], uint8_t *message, uint8_t BitOffSet, uint8_t NoOfBits)
{
    uint8_t i = 0;
    
    while(i < NoOfBits)
    {
        WriteByte(message, (state[0][(i/CELL_SIZE)]), BitOffSet+i, min(CELL_SIZE, NoOfBits-i));
        i += CELL_SIZE;
    	}
}
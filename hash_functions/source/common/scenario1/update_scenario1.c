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
#include <stdio.h>

#include "scenario1.h"
#include "cipher.h"

#define SUBSCENARIO 1

void UpdateScenario1(uint8_t *state, uint8_t *message)
{
#if (SUBSCENARIO == 0)
    
    uint16_t i;

    if(MESSAGE_SIZE <= BLOCK_SIZE)
    {
        Update(state, &message[0], MESSAGE_SIZE);		
    }
    else
    {
        /* Compress the remaining message blocks */
        for(i = 0; i < MESSAGE_SIZE; i += BLOCK_SIZE)
        {
            if(i+BLOCK_SIZE > MESSAGE_SIZE)
            {
                Update(state, &message[i], MESSAGE_SIZE - i);
            }
            else
            {
                Update(state, &message[i], BLOCK_SIZE);
            }
            
        }    
    } 

#elif (SUBSCENARIO == 1)

	uint16_t i, j;
	for(i = 0; i < MESSAGE_SIZE; i += j)
    {
    	j++;
        if(i+j > MESSAGE_SIZE)
        {
        	Update(state, &message[i], (MESSAGE_SIZE - i));
        }
        else
        {
        	Update(state, &message[i], j);
        }
        
    }

#endif

}

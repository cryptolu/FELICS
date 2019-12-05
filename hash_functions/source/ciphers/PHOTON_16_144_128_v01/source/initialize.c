/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2017 by Virat Shejwalkar <virat.shejwalkar@uni.lu0>
 ** This file is part of FELICS.
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

#include "cipher.h"
#include "constants.h"
#include "util.h"

void Initialize(uint8_t *state)
{

    photon_state_t *photon_state;
    photon_state = (photon_state_t *)state;
    uint8_t i, presets[3];
    for(i=0; i<STATE_SIZE; i++)
    {
    	state[i]=0;
    }
    presets[0] = (DIGEST_SIZE<<1);
    presets[1] = (8*BLOCK_SIZE);
    presets[2] = (8*BLOCK_SIZE);

    WordXorByte(photon_state->state, presets, 0, 30, 24);


}
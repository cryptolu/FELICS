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

#ifndef SCENARIO1_H
#define SCENARIO1_H

#include "constants.h"

#define KEY_SIZE 16

extern uint8_t MAC_KEY[KEY_SIZE];

/*
 *
 * Hash the given amount data by hmac principle
 * ... state - state of the hash permutation
 * ... message - the full message to be hashed
 *
 */
void UpdateScenario2HMAC(uint8_t *message, uint8_t *digest);

/*
 *
 * Hash the given amount data by prefix hash principle
 * ... state - state of the hash permutation
 * ... message - the full message to be hashed
 *
 */
void UpdateScenario2PMAC(uint8_t *message, uint8_t *digest);

#endif

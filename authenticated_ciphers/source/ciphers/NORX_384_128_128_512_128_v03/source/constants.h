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

#define BLOCK_SIZE 48           /* Replace with cipher block size */
#define KEY_SIZE 16             /* Replace with cipher key size */
#define NONCE_SIZE 16           /* Replace with cipher nonce size */
#define STATE_SIZE 64           /* Replace with cipher state size */
#define TAG_SIZE 16             /* Replace with cipher tag size */

#define TEST_MESSAGE_SIZE 17
#define TEST_ASSOCIATED_DATA_SIZE 7

#define NORX_W 32               /* Word size in bits */
#define NORX_L 4                /* Round number */
#define NORX_P 1                /* Parallelism degree */

#endif

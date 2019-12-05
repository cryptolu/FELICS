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
#include "cipher.h"
#include "constants.h"

RAM_DATA_BYTE RC[MATRIX_SIZE][12] = {
    {1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10},
    {0, 2, 6, 15, 12, 10, 7, 13, 8, 3, 4, 11},
    {2, 0, 4, 13, 14, 8, 5, 15, 10, 1, 6, 9},
    {6, 4, 0, 9, 10, 12, 1, 11, 14, 5, 2, 13},
    {7, 5, 1, 8, 11, 13, 0, 10, 15, 4, 3, 12},
    {5, 7, 3, 10, 9, 15, 2, 8, 13, 6, 1, 14}
};
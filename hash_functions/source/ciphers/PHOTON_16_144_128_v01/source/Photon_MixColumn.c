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

RAM_DATA_BYTE MixColMatrix[MATRIX_SIZE][MATRIX_SIZE] = {
    { 1,  2,  8,  5,  8,  2},
    { 2,  5,  1,  2,  6, 12},
    {12,  9, 15,  8,  8, 13},
    {13,  5, 11,  3, 10,  1},
    { 1, 15, 13, 14, 11,  8},
    { 8,  2,  3,  3,  2,  8}
}; 
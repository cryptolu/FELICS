/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

#ifndef SKINNY_REFERENCE
    #define SKINNY_REFERENCE

    #include <stdint.h>

    void AddKey(uint8_t state[4][4], uint8_t keyCells[3][4][4], int ver);

    void AddKeyPrecomputed(uint8_t state[4][4], uint8_t *roundKeys, int it, int ver);

    void AddKey_inv(uint8_t state[4][4], uint8_t keyCells[3][4][4], int ver);

    void AddConstants(uint8_t state[4][4], int r);

    void SubCell4(uint8_t state[4][4]);

    void SubCell4_inv(uint8_t state[4][4]);

    void SubCell8(uint8_t state[4][4]);

    void SubCell8_inv(uint8_t state[4][4]);

    void ShiftRows(uint8_t state[4][4]);

    void ShiftRows_inv(uint8_t state[4][4]);

    void MixColumn(uint8_t state[4][4]);

    void MixColumn_inv(uint8_t state[4][4]);

#endif

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
#include "constants.h"
#include "keccak_round.h"

#define index(x, y) (((x)%5)+5*((y)%5))

#define ROL8(a, offset) ((offset != 0) ? ((((uint8_t)a) << offset) ^ (((uint8_t)a) >> (sizeof(uint8_t)*8-offset))) : a)

/* ---------------------------------------------------------------- */

static void theta(uint8_t *A) {
    unsigned int x, y;
    uint8_t C[5], D[5];

    for (x = 0; x < 5; x++) {
        C[x] = 0;
        for (y = 0; y < 5; y++)
            C[x] ^= A[index(x, y)];
    }
    for (x = 0; x < 5; x++)
        D[x] = ROL8(C[(x + 1) % 5], 1) ^ C[(x + 4) % 5];
    for (x = 0; x < 5; x++)
        for (y = 0; y < 5; y++)
            A[index(x, y)] ^= D[x];
}

/* ---------------------------------------------------------------- */

static void rho(uint8_t *A) {
    unsigned int x, y;

    for (x = 0; x < 5; x++)
        for (y = 0; y < 5; y++)
            A[index(x, y)] =
                    ROL8(A[index(x, y)],
                    READ_KETJE_CONST_BYTE(KeccakRhoOffsets[index(x, y)]));
}

/* ---------------------------------------------------------------- */

static void pi(uint8_t *A) {
    unsigned int x, y;
    uint8_t tempA[25];

    for (x = 0; x < 5; x++)
        for (y = 0; y < 5; y++)
            tempA[index(x, y)] = A[index(x, y)];
    for (x = 0; x < 5; x++)
        for (y = 0; y < 5; y++)
            A[index(0 * x + 1 * y, 2 * x + 3 * y)] = tempA[index(x, y)];
}

/* ---------------------------------------------------------------- */

static void chi(uint8_t *A) {
    unsigned int x, y;
    uint8_t C[5];

    for (y = 0; y < 5; y++) {
        for (x = 0; x < 5; x++)
            C[x] = A[index(x, y)] ^ ((~A[index(x + 1, y)]) & A[index(x + 2,
                                    y)]);
        for (x = 0; x < 5; x++)
            A[index(x, y)] = C[x];
    }
}

/* ---------------------------------------------------------------- */

static void iota(uint8_t *A, uint8_t indexRound) {
    A[index(0, 0)] ^= READ_KETJE_CONST_BYTE(KeccakRoundConstants[indexRound]);
}

/* ---------------------------------------------------------------- */

void KeccakP200_Permute_Nrounds(uint8_t *state, unsigned int nrounds) {
    unsigned int i;

    for (i = (maxNrRounds - nrounds); i < maxNrRounds; i++) {
        KeccakP200Round(state, i);
    }
}
/*
 * void KeccakP200OnWords(uint8_t *state, unsigned int nrRounds)
 * {
 * unsigned int i;
 * 
 * for(i=(maxNrRounds-nrRounds); i<maxNrRounds; i++)
 * {
 * KeccakP200Round(state, i);
 * }
 * } */

void KeccakP200Round(uint8_t *state, unsigned int indexRound) {

    theta(state);


    rho(state);


    pi(state);


    chi(state);


    iota(state, indexRound);

}

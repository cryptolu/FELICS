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

#include <stdlib.h>
#include <stdio.h>

#include "cipher.h"
#include "constants.h"


void permute(uint8_t *state)
{
    uint8_t *X, *Y, *L;
    uint8_t h;
    uint16_t i;

    X = ( uint8_t * )malloc( ( N_LEN_U+NO_OF_ROUNDS )*sizeof( uint8_t ) );
    Y = ( uint8_t * )malloc( ( N_LEN_U+NO_OF_ROUNDS )*sizeof( uint8_t ) );
    L = ( uint8_t * )malloc( ( L_LEN_U+NO_OF_ROUNDS )*sizeof( uint8_t ) );

    /* local copy of the state in the registers*/
    for(i=0;i<N_LEN_U;i++)
    {
        //printf("%d %d %02x %02x\n", i, (i%8), state[i/8], ((state[i/8] >> (i%8))&0x01));
        X[i] = ( state[i/8] >> (7-i%8) ) & 0x01;
        Y[N_LEN_U - 1 - i] = ( state[STATE_SIZE - 1 - (i/8)] >> (i%8) ) & 0x01;
    }

    /* initialize the LFSR to 11..11 */
    for( i=0; i< L_LEN_U; ++i )
    {
        L[i]=0xFF;
    }
    
    /* iterate rounds */
    for( i=0; i< NO_OF_ROUNDS; ++i )
    {
        /* need X[i] as linear term only, for invertibility */
        X[N_LEN_U+i]  = X[i] ^ Y[i];
        X[N_LEN_U+i] ^= X[i+9] ^ X[i+14] ^ X[i+21] ^ X[i+28] ^
                        X[i+33] ^ X[i+37] ^ X[i+45] ^ X[i+52] ^ X[i+55] ^ X[i+50] ^
                        ( X[i+59] & X[i+55] ) ^ ( X[i+37] & X[i+33] ) ^ ( X[i+15] & X[i+9] ) ^
                        ( X[i+55] & X[i+52] & X[i+45] ) ^ ( X[i+33] & X[i+28] & X[i+21] ) ^
                        ( X[i+59] & X[i+45] & X[i+28] & X[i+9] ) ^
                        ( X[i+55] & X[i+52] & X[i+37] & X[i+33] ) ^
                        ( X[i+59] & X[i+55] & X[i+21] & X[i+15] ) ^
                        ( X[i+59] & X[i+55] & X[i+52] & X[i+45] & X[i+37] ) ^
                        ( X[i+33] & X[i+28] & X[i+21] & X[i+15] & X[i+9] ) ^
                        ( X[i+52] & X[i+45] & X[i+37] & X[i+33] & X[i+28] & X[i+21] );

        /* need Y[i] as linear term only, for invertibility */
        Y[N_LEN_U+i]  = Y[i];
        Y[N_LEN_U+i] ^= Y[i+7] ^ Y[i+16] ^ Y[i+20] ^ Y[i+30] ^
                        Y[i+35]  ^ Y[i+37] ^ Y[i+42] ^ Y[i+51] ^ Y[i+54] ^  Y[i+49] ^
                        ( Y[i+58] & Y[i+54] ) ^ ( Y[i+37] & Y[i+35] ) ^ ( Y[i+15] & Y[i+7] ) ^
                        ( Y[i+54] & Y[i+51] & Y[i+42] ) ^ ( Y[i+35] & Y[i+30] & Y[i+20] ) ^
                        ( Y[i+58] & Y[i+42] & Y[i+30] & Y[i+7] ) ^
                        ( Y[i+54] & Y[i+51] & Y[i+37] & Y[i+35] ) ^
                        ( Y[i+58] & Y[i+54] & Y[i+20] & Y[i+15] ) ^
                        ( Y[i+58] & Y[i+54] & Y[i+51] & Y[i+42] & Y[i+37] ) ^
                        ( Y[i+35] & Y[i+30] & Y[i+20] & Y[i+15] & Y[i+7] ) ^
                        ( Y[i+51] & Y[i+42] & Y[i+37] & Y[i+35] & Y[i+30] & Y[i+20] );

        /* need L[i] as linear term only, for invertibility */
        L[L_LEN_U+i]  = L[i];
        L[L_LEN_U+i] ^= L[i+3];

        /* compute output of the h function */
        h = X[i+25] ^ Y[i+59] ^ ( Y[i+3] & X[i+55] ) ^ ( X[i+46] & X[i+55] ) ^ ( X[i+55] & Y[i+59] ) ^
            ( Y[i+3] & X[i+25] & X[i+46] ) ^ ( Y[i+3] & X[i+46] & X[i+55] ) ^ ( Y[i+3] & X[i+46] & Y[i+59] ) ^
            ( X[i+25] & X[i+46] & Y[i+59] & L[i] ) ^ ( X[i+25] & L[i] );
        h ^= X[i+1] ^ Y[i+2] ^ X[i+4] ^ Y[i+10] ^ X[i+31] ^ Y[i+43] ^ X[i+56] ^ L[i];

        /* feedback of h into the registers */
        X[N_LEN_U+i] ^= h;
        Y[N_LEN_U+i] ^= h;
    }
    
    /* Update the state value from X and Y */
    for(i=0; i<64; i=i+8)
    {
        state[i/8] = ( ((X[NO_OF_ROUNDS + i]&0x01) << 7) | ((X[NO_OF_ROUNDS + i + 1]&0x01) << 6) | ((X[NO_OF_ROUNDS + i + 2]&0x01) << 5) | ((X[NO_OF_ROUNDS + i + 3]&0x01) << 4) |
                       ((X[NO_OF_ROUNDS + i + 4]&0x01) << 3) | ((X[NO_OF_ROUNDS + i + 5]&0x01) << 2) | ((X[NO_OF_ROUNDS + i + 6]&0x01) << 1) | (X[NO_OF_ROUNDS + i + 7]&0x01)
                     );
        state[9+(i/8)] = ( ((Y[NO_OF_ROUNDS + 4 + i]&0x01) << 7) | ((Y[NO_OF_ROUNDS + 4 + i + 1]&0x01) << 6) | ((Y[NO_OF_ROUNDS + 4 + i + 2]&0x01) << 5) | ((Y[NO_OF_ROUNDS + 4 + i + 3]&0x01) << 4) |
                       ((Y[NO_OF_ROUNDS + 4 + i + 4]&0x01) << 3) | ((Y[NO_OF_ROUNDS + 4 + i + 5]&0x01) << 2) | ((Y[NO_OF_ROUNDS + 4 + i + 6]&0x01) << 1) | (Y[NO_OF_ROUNDS + 4 + i + 7]&0x01)
                     );
    }
    state[8] = ( ((X[NO_OF_ROUNDS + 64]&0x01) << 7) | ((X[NO_OF_ROUNDS + 65]&0x01) << 6) | ((X[NO_OF_ROUNDS + 66]&0x01) << 5) | ((X[NO_OF_ROUNDS + 67]&0x01) << 4) |
                       ((Y[NO_OF_ROUNDS]&0x01) << 3) | ((Y[NO_OF_ROUNDS + 1]&0x01) << 2) | ((Y[NO_OF_ROUNDS + 2]&0x01) << 1) | (Y[NO_OF_ROUNDS + 3]&0x01)
               );
   
    free( X );
    free( Y );
    free( L );
}
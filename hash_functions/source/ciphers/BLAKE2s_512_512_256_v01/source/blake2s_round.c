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
#include <inttypes.h>

#include <blake2-impl.h>
#include "constants.h"

void G(uint8_t r, uint8_t i, uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d, uint32_t *M)
{
	*a = *a + *b + M[blake2s_sigma[r][2*i+0]];
    *d = rotr32(*d ^ *a, 16);        
    *c = *c + *d;             
    *b = rotr32(*b ^ *c, 12);                
    *a = *a + *b + M[blake2s_sigma[r][2*i+1]]; 
    *d = rotr32(*d ^ *a, 8);                   
    *c = *c + *d;                              
    *b = rotr32(*b ^ *c, 7);           
}

#ifdef MSP
void __attribute__((optimize(0))) ROUND(uint8_t r, uint32_t *V, uint32_t *M)
#else
void ROUND(uint8_t r, uint32_t *V, uint32_t *M)
#endif
{
    G(r,0,&V[ 0],&V[ 4],&V[ 8],&V[12], M);          
    G(r,1,&V[ 1],&V[ 5],&V[ 9],&V[13], M);
    G(r,2,&V[ 2],&V[ 6],&V[10],&V[14], M);
    G(r,3,&V[ 3],&V[ 7],&V[11],&V[15], M);
    G(r,4,&V[ 0],&V[ 5],&V[10],&V[15], M);
    G(r,5,&V[ 1],&V[ 6],&V[11],&V[12], M);
    G(r,6,&V[ 2],&V[ 7],&V[ 8],&V[13], M);
    G(r,7,&V[ 3],&V[ 4],&V[ 9],&V[14], M);
}
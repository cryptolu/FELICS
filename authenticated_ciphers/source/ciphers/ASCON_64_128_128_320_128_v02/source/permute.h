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

#ifndef PERMUTE_H
#define PERMUTE_H

#define ROUND_32(C_e,C_o) ({\
    /* round constant */\
    x2_e ^= C_e;\
    x2_o ^= C_o;\
    /* s-box layer */\
    t0_e = x0_e ^ x4_e;       t1_e = x4_e ^ x3_e;    x2_e = x2_e ^ x1_e;\
    t0_o = x0_o ^ x4_o;       t1_o = x4_o ^ x3_o;    x2_o = x2_o ^ x1_o;\
    x0_e = x2_e & (~x1_e);    x0_e = t0_e ^ x0_e; \
    x0_o = x2_o & (~x1_o);    x0_o = t0_o ^ x0_o; \
    x4_e = x2_e & (~x1_e);    x4_e = x0_e ^ x4_e;\
    x4_o = x2_o & (~x1_o);    x4_o = x0_o ^ x4_o;\
    x4_e = x1_e & (~x4_e);    x4_e = x4_e ^ t1_e;\
    x4_o = x1_o & (~x4_o);    x4_o = x4_o ^ t1_o;\
    t0_e = x2_e & (~x1_e);    t0_e = t0_e ^ x0_e;\
    t0_o = x2_o & (~x1_o);    t0_o = t0_o ^ x0_o;\
    t0_e = t0_e & (~t1_e);    t0_e = t0_e ^ x3_e;\
    t0_o = t0_o & (~t1_o);    t0_o = t0_o ^ x3_o;\
    t1_e = x2_e & (~x1_e);    t1_e = t1_e ^ x0_e;\
    t1_o = x2_o & (~x1_o);    t1_o = t1_o ^ x0_o;\
    t1_e = x1_e & (~t1_e);    t1_e = t1_e ^ x4_e;\
    t1_o = x1_o & (~t1_o);    t1_o = t1_o ^ x4_o;\
    t1_e = t1_e & (~x3_e);    t1_e = t1_e ^ x2_e;\
    t1_o = t1_o & (~x3_o);    t1_o = t1_o ^ x2_o;\
    x2_e = x3_e & (~x2_e);    x1_e = x1_e ^ x2_e;\
    x2_o = x3_o & (~x2_o);    x1_o = x1_o ^ x2_o;\
    x1_e = x1_e ^ x0_e;    x0_e = x0_e ^ x4_e;    x3_e = t0_e ^ t1_e;    x2_e =~ t1_e;\
    x1_o = x1_o ^ x0_o;    x0_o = x0_o ^ x4_o;    x3_o = t0_o ^ t1_o;    x2_o =~ t1_o;\
    /* linear layer */\
    t0_e  = x0_e;    t0_o  = x0_o; \
    t1_e  = x1_e;    t1_o  = x1_o;\
    x0_e ^= ROTR32(t0_o, R_O[0][0]);\
    x0_o ^= ROTR32(t0_e, R_E[0][0]);\
    x1_e ^= ROTR32(t1_o, R_O[1][0]);\
    x1_o ^= ROTR32(t1_e, R_E[1][0]);\
    x0_e ^= ROTR32(t0_e, R_E[0][1]);\
    x0_o ^= ROTR32(t0_o, R_O[0][1]);\
    x1_e ^= ROTR32(t1_o, R_O[1][1]);\
    x1_o ^= ROTR32(t1_e, R_E[1][1]);\
    t0_e  = x2_e;    t0_o  = x2_o;\
    t1_e  = x3_e;    t1_o  = x3_o;\
    x2_e ^= ROTR32(t0_o, R_O[2][0]);\
    x2_o ^= ROTR32(t0_e, R_E[2][0]);\
    x3_e ^= ROTR32(t1_e, R_E[3][0]);\
    x3_o ^= ROTR32(t1_o, R_O[3][0]);\
    x2_e ^= ROTR32(t0_e, R_E[2][1]);\
    x2_o ^= ROTR32(t0_o, R_O[2][1]);\
    x3_e ^= ROTR32(t1_o, R_O[3][1]);\
    x3_o ^= ROTR32(t1_e, R_E[3][1]);\
    t0_e  = x4_e;\
    t0_o  = x4_o;\
    x4_e ^= ROTR32(t0_o, R_O[4][0]);\
    x4_o ^= ROTR32(t0_e, R_E[4][0]);\
    x4_e ^= ROTR32(t0_o, R_O[4][1]);\
    x4_o ^= ROTR32(t0_e, R_E[4][1]);\
  })

#define P12_32 ({\
  ROUND_32(0xc,0xc);\
  ROUND_32(0x9,0xc);\
  ROUND_32(0xc,0x9);\
  ROUND_32(0x9,0x9);\
  ROUND_32(0x6,0xc);\
  ROUND_32(0x3,0xc);\
  ROUND_32(0x6,0x9);\
  ROUND_32(0x3,0x9);\
  ROUND_32(0xc,0x6);\
  ROUND_32(0x9,0x6);\
  ROUND_32(0xc,0x3);\
  ROUND_32(0x9,0x3);\
})

#define P6_32 ({\
  ROUND_32(0x6,0x9);\
  ROUND_32(0x3,0x9);\
  ROUND_32(0xc,0x6);\
  ROUND_32(0x9,0x6);\
  ROUND_32(0xc,0x3);\
  ROUND_32(0x9,0x3);\
})

void permutation(uint8_t *state, uint8_t rounds);

#endif

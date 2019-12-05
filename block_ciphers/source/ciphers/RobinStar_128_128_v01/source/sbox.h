/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Johann Großschädl <johann.groszschaedl@uni.lu>
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

#ifndef SBOX_H
#define SBOX_H


#define Class13(A,B,C,D,X,Y,Z,T) do {  \
  uint16_t __a, __b, __c, __d;         \
  __a  = A & B;                        \
  __a ^= C;                            \
  __c  = B | C;                        \
  __c ^= D;                            \
  __d  = __a & D;                      \
  __d ^= A;                            \
  __b  = __c & A;                      \
  __b ^= B;                            \
  X ^= __a;                            \
  Y ^= __b;                            \
  Z ^= __c;                            \
  T ^= __d;                            \
} while (0)


#define SBOX(x) do {                                       \
  Class13(x[4], x[5], x[6], x[7], x[0], x[1], x[2], x[3]); \
  Class13(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]); \
  Class13(x[4], x[5], x[6], x[7], x[0], x[1], x[2], x[3]); \
} while(0)


#endif /* SBOX_H */

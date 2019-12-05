/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2017 University of Luxembourg
 *
 * Written in 2017 by Virat Shejwalkar <virat.shejwalkar@uni.lu>,
 *                    Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

/* Macros for use in GCC basic asm statements for the MSP */

#include "stringify.h"

#define ONE #1

/* x += y */
#define ADD_(x1, x0, y1, y0)     \
  add  x0, y0               \n\t \
  addc x1, y1               \n\t

/* x -= y */
#define SUB_(x1, x0, y1, y0)     \
  sub x0, y0                \n\t \
  subc x1, y1               \n\t 

/* x ^= y */
#define XOR_(x1, x0, y1, y0)     \
  xor x0, y0                \n\t \
  xor x1, y1                \n\t

/* Left circular shift in place */
#define LCS1_(x1, x0)            \
  rla x0                    \n\t \
  rlc x1                    \n\t \
  adc x0                    \n\t

/* Right circular shift in place */
#define RCS1_(x1, x0)            \
  bit ONE, x0               \n\t \
  rrc x1                    \n\t \
  rrc x0                    \n\t

#define LCS5_(x1, x0)            \
  LCS1_(x1, x0)                  \
  LCS1_(x1, x0)                  \
  LCS1_(x1, x0)                  \
  LCS1_(x1, x0)                  \
  LCS1_(x1, x0)

#define RCS5_(x1, x0)            \
  RCS1_(x1, x0)                  \
  RCS1_(x1, x0)                  \
  RCS1_(x1, x0)                  \
  RCS1_(x1, x0)                  \
  RCS1_(x1, x0)

#define LCS7_(x1, x0, tmp)       \
  LCS8_(x1, x0, tmp)             \
  RCS1_(x1, x0)

#define RCS7_(x1, x0, tmp)       \
  RCS8_(x1, x0, tmp)             \
  LCS1_(x1, x0)

#define LCS8_(x1, x0, tmp)       \
  swpb  x0                  \n\t \
  swpb  x1                  \n\t \
  mov.b x0, tmp             \n\t \
  xor.b x1, tmp             \n\t \
  xor   tmp, x1             \n\t \
  xor   tmp, x0             \n\t

#define RCS8_(x1, x0, tmp)       \
  mov.b x0, tmp             \n\t \
  xor.b x1, tmp             \n\t \
  swpb x0                   \n\t \
  swpb x1                   \n\t \
  swpb tmp                  \n\t \
  xor tmp, x0               \n\t \
  xor tmp, x1               \n\t

#define LCS13_(x1, x0, tmp)      \
  LCS16_(x1, x0, tmp)            \
  RCS1_(x1, x0)                  \
  RCS1_(x1, x0)                  \
  RCS1_(x1, x0)

#define RCS13_(x1, x0, tmp)      \
  RCS16_(x1, x0, tmp)            \
  LCS1_(x1, x0)                  \
  LCS1_(x1, x0)                  \
  LCS1_(x1, x0)

#define LCS16_(x1, x0, tmp)      \
  mov x1, tmp               \n\t \
  mov x0, x1                \n\t \
  mov tmp, x0               \n\t 

#define RCS16_(x1, x0, tmp)      \
  mov x1, tmp               \n\t \
  mov x0, x1                \n\t \
  mov tmp, x0               \n\t

/*Stringify the above functions*/

#define ADD(x1, x0, y1, y0)      \
  STR(ADD_(x1, x0, y1, y0))

#define SUB(x1, x0, y1, y0)      \
  STR(SUB_(x1, x0, y1, y0))

#define XOR(x1, x0, y1, y0)      \
  STR(XOR_(x1, x0, y1, y0))

#define LCS1(x1, x0)             \
  STR(LCS1_(x1, x0))

#define RCS1(x1, x0)             \
  STR(RCS1_(x1, x0))

#define LCS5(x1, x0)             \
  STR(LCS5_(x1, x0))

#define RCS5(x1, x0)             \
  STR(RCS5_(x1, x0))

#define LCS7(x1, x0, tmp)        \
  STR(LCS7_(x1, x0, tmp))

#define RCS7(x1, x0, tmp)        \
  STR(RCS7_(x1, x0, tmp))

#define LCS8(x1, x0, tmp)        \
  STR(LCS8_(x1, x0, tmp))

#define RCS8(x1, x0, tmp)        \
  STR(RCS8_(x1, x0, tmp))

#define LCS13(x1, x0, tmp)       \
  STR(LCS13_(x1, x0, tmp))

#define RCS13(x1, x0, tmp)       \
  STR(RCS13_(x1, x0, tmp))

#define LCS16(x1, x0, tmp)       \
  STR(LCS16_(x1, x0, tmp))

#define RCS16(x1, x0, tmp)       \
  STR(RCS16_(x1, x0, tmp))

#define CHASKEY_ENC_ROUND(x7, x6, x5, x4, x3, x2, x1, x0, tmp) \
  ADD(x3, x2, x1, x0)                                          \
  LCS5(x3, x2)                                                 \
  XOR(x1, x0, x3, x2)                                          \
  LCS16(x1, x0, tmp)                                           \
  ADD(x7, x6, x5, x4)                                          \
  LCS8(x7, x6, tmp)                                            \
  XOR(x5, x4, x7, x6)                                          \
  ADD(x7, x6, x1, x0)                                          \
  LCS13(x7, x6, tmp)                                           \
  XOR(x1, x0, x7, x6)                                          \
  ADD(x3, x2, x5, x4)                                          \
  LCS7(x3, x2, tmp)                                            \
  XOR(x5, x4, x3, x2)                                          \
  LCS16(x5, x4, tmp)

#define CHASKEY_DEC_ROUND(x7, x6, x5, x4, x3, x2, x1, x0, tmp) \
  RCS16(x5, x4, tmp)                                           \
  XOR(x5, x4, x3, x2)                                          \
  RCS7(x3, x2, tmp)                                            \
  SUB(x3, x2, x5, x4)                                          \
  XOR(x1, x0, x7, x6)                                          \
  RCS13(x7, x6, tmp)                                           \
  SUB(x7, x6, x1, x0)                                          \
  XOR(x5, x4, x7, x6)                                          \
  RCS8(x7, x6, tmp)                                            \
  SUB(x7, x6, x5, x4)                                          \
  RCS16(x1, x0, tmp)                                           \
  XOR(x1, x0, x3, x2)                                          \
  RCS5(x3, x2)                                                 \
  SUB(x3, x2, x1, x0)

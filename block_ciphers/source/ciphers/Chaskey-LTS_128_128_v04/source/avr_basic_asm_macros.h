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

/* Macros for use in GCC basic asm statements for the AVR */

#include "stringify.h"


/* x += y */
#define ADD_(x3, x2, x1, x0, y3, y2, y1, y0)                    \
  add x0, y0                                               \n\t \
  adc x1, y1                                               \n\t \
  adc x2, y2                                               \n\t \
  adc x3, y3                                               \n\t

/* x -= y */
#define SUB_(x3, x2, x1, x0, y3, y2, y1, y0)                    \
  sub x0, y0                                               \n\t \
  sbc x1, y1                                               \n\t \
  sbc x2, y2                                               \n\t \
  sbc x3, y3                                               \n\t

/* x ^= y */
#define XOR_(x3, x2, x1, x0, y3, y2, y1, y0)                    \
  eor x0, y0                                               \n\t \
  eor x1, y1                                               \n\t \
  eor x2, y2                                               \n\t \
  eor x3, y3                                               \n\t \


/* Left circular shift in place */
#define LCS1_(x3, x2, x1, x0)                                   \
  lsl x0                                                   \n\t \
  rol x1                                                   \n\t \
  rol x2                                                   \n\t \
  rol x3                                                   \n\t \
  adc x0, __zero_reg__                                     \n\t

/*
 * Right circular shift in place
 *
 * Store the least significant bit in the T flag and copy it to the most
 * significant bit at the end
 */
#define RCS1_(x3, x2, x1, x0)                                   \
  bst x0, 0                                                \n\t \
  ror x3                                                   \n\t \
  ror x2                                                   \n\t \
  ror x1                                                   \n\t \
  ror x0                                                   \n\t \
  bld x3, 7                                                \n\t


#define LCS5_(x3, x2, x1, x0, t0, t1, t2, reg0, reg1)           \
  push reg1                                                \n\t \
                                                           \n\t \
  ldi t0, 32                                               \n\t \
                                                                \
  mov t1, x1                                               \n\t \
  mov t2, x3                                               \n\t \
                                                                \
  mul x0, t0                                               \n\t \
  movw x0, reg0                                            \n\t \
                                                                \
  mul x2, t0                                               \n\t \
  movw x2, reg0                                            \n\t \
                                                                \
  mul t1, t0                                               \n\t \
  eor x1, reg0                                             \n\t \
  eor x2, reg1                                             \n\t \
                                                                \
  mul t2, t0                                               \n\t \
  eor x3, reg0                                             \n\t \
  eor x0, reg1                                             \n\t \
                                                           \n\t \
  pop reg1                                                 \n\t

#define RCS5_(x3, x2, x1, x0, temp)                             \
  RCS8_(x3, x2, x1, x0, temp)                                   \
  LCS1_(x3, x2, x1, x0)                                         \
  LCS1_(x3, x2, x1, x0)                                         \
  LCS1_(x3, x2, x1, x0)                                         


#define LCS7_(x3, x2, x1, x0, temp)                             \
  LCS8_(x3, x2, x1, x0, temp)                                   \
  RCS1_(x3, x2, x1, x0)

#define RCS7_(x3, x2, x1, x0, temp)                             \
  RCS8_(x3, x2, x1, x0, temp)                                   \
  LCS1_(x3, x2, x1, x0)


#define LCS8_(x3, x2, x1, x0, temp)                             \
  mov temp, x3                                             \n\t \
  mov x3, x2                                               \n\t \
  mov x2, x1                                               \n\t \
  mov x1, x0                                               \n\t \
  mov x0, temp                                              \n\t

#define RCS8_(x3, x2, x1, x0, temp)                             \
  mov temp, x0                                             \n\t \
  mov x0, x1                                               \n\t \
  mov x1, x2                                               \n\t \
  mov x2, x3                                               \n\t \
  mov x3, temp                                             \n\t


#define LCS13_(x3, x2, x1, x0, t0, t1)                          \
  LCS16_(x3, x2, x1, x0, t0, t1)                                \
  RCS1_(x3, x2, x1, x0)                                         \
  RCS1_(x3, x2, x1, x0)                                         \
  RCS1_(x3, x2, x1, x0)

#define RCS13_(x3, x2, x1, x0, t0, t1)                          \
  RCS16_(x3, x2, x1, x0, t0, t1)                                \
  LCS1_(x3, x2, x1, x0)                                         \
  LCS1_(x3, x2, x1, x0)                                         \
  LCS1_(x3, x2, x1, x0)


/* (t0, t1) pair with t0 - even register; e.g. (r20, r21) */
#define LCS16_(x3, x2, x1, x0, t0, t1)                          \
  movw t0, x2                                              \n\t \
  movw x2, x0                                              \n\t \
  movw x0, t0                                              \n\t

/* (t0, t1) pair with t0 - even register; e.g. (r20, r21) */
#define RCS16_(x3, x2, x1, x0, t0, t1)                          \
  movw t0, x0                                              \n\t \
  movw x0, x2                                              \n\t \
  movw x2, t0                                              \n\t


/* Make stringified versions of these macros useful externally */

#define ADD(x3, x2, x1, x0, y3, y2, y1, y0)                     \
  STR(ADD_(x3, x2, x1, x0, y3, y2, y1, y0))

#define SUB(x3, x2, x1, x0, y3, y2, y1, y0)                     \
  STR(SUB_(x3, x2, x1, x0, y3, y2, y1, y0))

#define LCS1(x3, x2, x1, x0)                                    \
  STR(LCS1_(x3, x2, x1, x0))

#define RCS1(x3, x2, x1, x0)                                    \
  STR(RCS1_(x3, x2, x1, x0))

#define LCS5(x3, x2, x1, x0, t0, t1, t2, reg0, reg1)            \
  STR(LCS5_(x3, x2, x1, x0, t0, t1, t2, reg0, reg1))

#define RCS5(x3, x2, x1, x0, temp)                              \
  STR(RCS5_(x3, x2, x1, x0, temp))

#define LCS7(x3, x2, x1, x0, temp)                              \
  STR(LCS7_(x3, x2, x1, x0, temp))

#define RCS7(x3, x2, x1, x0, temp)                              \
  STR(RCS7_(x3, x2, x1, x0, temp))

#define LCS8(x3, x2, x1, x0, temp)                              \
  STR(LCS8_(x3, x2, x1, x0, temp))

#define RCS8(x3, x2, x1, x0, temp)                              \
  STR(RCS8_(x3, x2, x1, x0, temp))

#define LCS13(x3, x2, x1, x0, t0, t1)                           \
  STR(LCS13_(x3, x2, x1, x0, t0, t1))

#define RCS13(x3, x2, x1, x0, t0, t1)                           \
  STR(RCS13_(x3, x2, x1, x0, t0, t1))

#define LCS16(x3, x2, x1, x0, t0, t1)                           \
  STR(LCS16_(x3, x2, x1, x0, t0, t1))

#define RCS16(x3, x2, x1, x0, t0, t1)                           \
  STR(RCS16_(x3, x2, x1, x0, t0, t1))

#define XOR(x3, x2, x1, x0, y3, y2, y1, y0)                     \
  STR(XOR_(x3, x2, x1, x0, y3, y2, y1, y0))

#define CHASKEY_ENC_ROUND(x15, x14, x13, x12, x11, x10, x9, x8, x7, x6, x5, x4, x3, x2, x1, x0, t0, t1, t2, reg0, reg1) \
  ADD(x3, x2, x1, x0, x7, x6, x5, x4)                                                                                   \
  LCS5(x7, x6, x5, x4, t0, t1, t2, reg0, reg1)                                                                          \
  XOR(x7, x6, x5, x4, x3, x2, x1, x0)                                                                                   \
  LCS16(x3, x2, x1, x0, t0, t1)                                                                                         \
  ADD(x11, x10, x9, x8, x15, x14, x13, x12)                                                                             \
  LCS8(x15, x14, x13, x12, t0)                                                                                          \
  XOR(x15, x14, x13, x12, x11, x10, x9, x8)                                                                             \
  ADD(x3, x2, x1, x0, x15, x14, x13, x12)                                                                               \
  LCS13(x15, x14, x13, x12, t0, t1)                                                                                     \
  XOR(x15, x14, x13, x12, x3, x2, x1, x0)                                                                               \
  ADD(x11, x10, x9, x8, x7, x6, x5, x4)                                                                                 \
  LCS7(x7, x6, x5, x4, t0)                                                                                              \
  XOR(x7, x6, x5, x4, x11, x10, x9, x8)                                                                                 \
  LCS16(x11, x10, x9, x8, t0, t1)

#define CHASKEY_DEC_ROUND(x15, x14, x13, x12, x11, x10, x9, x8, x7, x6, x5, x4, x3, x2, x1, x0, t0, t1) \
  RCS16(x11, x10, x9, x8, t0, t1)                                                                       \
  XOR(x7, x6, x5, x4, x11, x10, x9, x8)                                                                 \
  RCS7(x7, x6, x5, x4, t0)                                                                              \
  SUB(x11, x10, x9, x8, x7, x6, x5, x4)                                                                 \
  XOR(x15, x14, x13, x12, x3, x2, x1, x0)                                                               \
  RCS13(x15, x14, x13, x12, t0, t1)                                                                     \
  SUB(x3, x2, x1, x0, x15, x14, x13, x12)                                                               \
  XOR(x15, x14, x13, x12, x11, x10, x9, x8)                                                             \
  RCS8(x15, x14, x13, x12, t0)                                                                          \
  SUB(x11, x10, x9, x8, x15, x14, x13, x12)                                                             \
  RCS16(x3, x2, x1, x0, t0, t1)                                                                         \
  XOR(x7, x6, x5, x4, x3, x2, x1, x0)                                                                   \
  RCS5(x7, x6, x5, x4, t0)                                                                              \
  SUB(x3, x2, x1, x0, x7, x6, x5, x4)

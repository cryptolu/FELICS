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


#define SBOX(x) do {                       \
  uint16_t __t0, __t1, __t2;               \
  /* S5 */                                 \
  x[2] ^= x[0] & x[1];                     \
  x[1] ^= x[2];                            \
  x[3] ^= x[0] & x[4];                     \
  x[2] ^= x[3];                            \
  x[0] ^= x[1] & x[3];                     \
  x[4] ^= x[1];                            \
  x[1] ^= x[2] & x[4];                     \
  x[1] ^= x[0];                            \
  /* Extend-Xor */                         \
  x[0] ^= x[5];                            \
  x[1] ^= x[6];                            \
  x[2] ^= x[7];                            \
  /* Key */                                \
  x[3] = ~x[3];                            \
  x[4] = ~x[4];                            \
  /* S3: 3-bit Keccak S-box */             \
  __t0 = x[5]; __t1 = x[6]; __t2 = x[7];   \
  x[5] ^= (~__t1) & __t2;                  \
  x[6] ^= (~__t2) & __t0;                  \
  x[7] ^= (~__t0) & __t1;                  \
  /* Truncate-Xor */                       \
  x[5] ^= x[0];                            \
  x[6] ^= x[1];                            \
  x[7] ^= x[2];                            \
  /* S5 */                                 \
  x[2] ^= x[0] & x[1];                     \
  x[1] ^= x[2];                            \
  x[3] ^= x[0] & x[4];                     \
  x[2] ^= x[3];                            \
  x[0] ^= x[1] & x[3];                     \
  x[4] ^= x[1];                            \
  x[1] ^= x[2] & x[4];                     \
  x[1] ^= x[0];                            \
} while(0)


#endif /* SBOX_H */

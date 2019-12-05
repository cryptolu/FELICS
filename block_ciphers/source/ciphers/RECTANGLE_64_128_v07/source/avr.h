/*
 *
 * Chinese Academy of Sciences
 * State Key Laboratory of Information Security, 
 * Institute of Information Engineering
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2017 Chinese Academy of Sciences
 *
 * Written in 2017 by Luo Peng <luopeng@iie.ac.cn>
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

#define N12    12

// key schedule
#define key_sbox(k0, k4, k8, k12, t0, t1) \
    mov    t0,    k8     \n\t \
    eor    k8,    k4     \n\t \
    com    k4            \n\t \
    mov    t1,    k0     \n\t \
    and    k0,    k4     \n\t \
    or     k4,    k12    \n\t \
    eor    k4,    t1     \n\t \
    eor    k12,   t0     \n\t \
    eor    k0,    k12    \n\t \
    and    k12,   k4     \n\t \
    eor    k12,   k8     \n\t \
    or     k8,    k0     \n\t \
    eor    k8,    k4     \n\t \
    eor    k4,    t0     \n\t

// sbox
#define sbox(s0, s1, s2, s3, s4, s5, s6, s7, t0, t1, t2, t3) \
    movw   t0,    s4     \n\t \
    eor    s4,    s2     \n\t \
    eor    s5,    s3     \n\t \
    com    s2            \n\t \
    com    s3            \n\t \
    movw   t2,    s0     \n\t \
    and    s0,    s2     \n\t \
    and    s1,    s3     \n\t \
    or     s2,    s6     \n\t \
    or     s3,    s7     \n\t \
    eor    s6,    t0     \n\t \
    eor    s7,    t1     \n\t \
    eor    s0,    s6     \n\t \
    eor    s1,    s7     \n\t \
    eor    s2,    t2     \n\t \
    eor    s3,    t3     \n\t \
    and    s6,    s2     \n\t \
    and    s7,    s3     \n\t \
    eor    s6,    s4     \n\t \
    eor    s7,    s5     \n\t \
    or     s4,    s0     \n\t \
    or     s5,    s1     \n\t \
    eor    s4,    s2     \n\t \
    eor    s5,    s3     \n\t \
    eor    s2,    t0     \n\t \
    eor    s3,    t1     \n\t

// invert sbox
#define invert_sbox(s0, s1, s2, s3, s4, s5, s6, s7, t0, t1) \
    movw   t0,    s0     \n\t \
    and    s0,    s4     \n\t \
    and    s1,    s5     \n\t \
    eor    s0,    s6     \n\t \
    eor    s1,    s7     \n\t \
    or     s6,    t0     \n\t \
    or     s7,    t1     \n\t \
    eor    s6,    s4     \n\t \
    eor    s7,    s5     \n\t \
    eor    s2,    s6     \n\t \
    eor    s3,    s7     \n\t \
    movw   s4,    s2     \n\t \
    eor    s2,    t0     \n\t \
    eor    s3,    t1     \n\t \
    eor    s2,    s0     \n\t \
    eor    s3,    s1     \n\t \
    com    s6            \n\t \
    com    s7            \n\t \
    movw   t0,    s6     \n\t \
    or     s6,    s2     \n\t \
    or     s7,    s3     \n\t \
    eor    s6,    s0     \n\t \
    eor    s7,    s1     \n\t \
    and    s0,    s2     \n\t \
    and    s1,    s3     \n\t \
    eor    s0,    t0     \n\t \
    eor    s1,    t1     \n\t

// AddRoundKey and Inverse AddRoundKey
#if defined(SCENARIO) && (SCENARIO_2 == SCENARIO)
#define keyxor(kt0, kt1, s0, s1, s2, s3, s4, s5, s6, s7, k) \
    eor    s3,    kt0    \n\t \
    eor    s7,    kt1    \n\t \
    lpm    k,     z+     \n\t \
    eor    s0,    k      \n\t \
    lpm    k,     z+     \n\t \
    eor    s2,    k      \n\t \
    lpm    k,     z+     \n\t \
    eor    s4,    k      \n\t \
    lpm    k,     z+     \n\t \
    eor    s6,    k      \n\t \
    lpm    kt0,   z+     \n\t \
    eor    s5,    kt0    \n\t \
    lpm    kt1,   z+     \n\t \
    eor    s1,    kt1    \n\t

#define dec_keyxor(kt0, kt1, s0, s1, s2, s3, s4, s5, s6, s7, k) \
    eor    s1,    kt1    \n\t \
    eor    s5,    kt0    \n\t \
    lpm    kt0,   z+     \n\t \
    eor    s3,    kt0    \n\t \
    lpm    kt1,   z+     \n\t \
    eor    s7,    kt1    \n\t \
    lpm    k,     z+     \n\t \
    eor    s0,    k      \n\t \
    lpm    k,     z+     \n\t \
    eor    s2,    k      \n\t \
    lpm    k,     z+     \n\t \
    eor    s4,    k      \n\t \
    lpm    k,     z+     \n\t \
    eor    s6,    k      \n\t \
    sbiw   r30,   N12    \n\t

#else
#define keyxor(kt0, kt1, s0, s1, s2, s3, s4, s5, s6, s7, k) \
    eor    s3,    kt0    \n\t \
    eor    s7,    kt1    \n\t \
    ld     k,     z+     \n\t \
    eor    s0,    k      \n\t \
    ld     k,     z+     \n\t \
    eor    s2,    k      \n\t \
    ld     k,     z+     \n\t \
    eor    s4,    k      \n\t \
    ld     k,     z+     \n\t \
    eor    s6,    k      \n\t \
    ld     kt0,   z+     \n\t \
    eor    s5,    kt0    \n\t \
    ld     kt1,   z+     \n\t \
    eor    s1,    kt1    \n\t

#define dec_keyxor(kt0, kt1, s0, s1, s2, s3, s4, s5, s6, s7, k) \
    eor    s1,    kt1    \n\t \
    eor    s5,    kt0    \n\t \
    ld     k,     -z     \n\t \
    eor    s6,    k      \n\t \
    ld     k,     -z     \n\t \
    eor    s4,    k      \n\t \
    ld     k,     -z     \n\t \
    eor    s2,    k      \n\t \
    ld     k,     -z     \n\t \
    eor    s0,    k      \n\t \
    ld     kt1,   -z     \n\t \
    eor    s7,    kt1    \n\t \
    ld     kt0,   -z     \n\t \
    eor    s3,    kt0    \n\t

#endif
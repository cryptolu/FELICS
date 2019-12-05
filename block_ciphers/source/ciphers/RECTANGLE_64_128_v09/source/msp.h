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

#define ONE #1

#define sbox(s0, s1, s2, s3, t0, t1)  \
    mov    s2,    t0    \n\t \
    xor    s1,    s2    \n\t \
    inv    s1           \n\t \
    mov    s0,    t1    \n\t \
    and    s1,    s0    \n\t \
    bis    s3,    s1    \n\t \
    xor    t1,    s1    \n\t \
    xor    t0,    s3    \n\t \
    xor    s3,    s0    \n\t \
    and    s1,    s3    \n\t \
    xor    s2,    s3    \n\t \
    bis    s0,    s2    \n\t \
    xor    s1,    s2    \n\t \
    xor    t0,    s1    \n\t

#define invert_sbox(s0, s1, s2, s3, t0, t1)  \
    mov    s0,    t0    \n\t  \
    and    s2,    s0    \n\t  \
    xor    s3,    s0    \n\t  \
    bis    t0,    s3    \n\t  \
    xor    s2,    s3    \n\t  \
    xor    s3,    s1    \n\t  \
    mov    s1,    s2    \n\t  \
    xor    t0,    s1    \n\t  \
    xor    s0,    s1    \n\t  \
    inv    s3           \n\t  \
    mov    s3,    t0    \n\t  \
    bis    s1,    s3    \n\t  \
    xor    s0,    s3    \n\t  \
    and    s1,    s0    \n\t  \
    xor    t0,    s0    \n\t

#define ksche_sbox(s0, s1, s2, s3, t0, t1)  \
    mov.b  s2,    t0    \n\t  \
    xor.b  s1,    s2    \n\t  \
    inv.b  s1           \n\t  \
    mov.b  s0,    t1    \n\t  \
    and.b  s1,    s0    \n\t  \
    bis.b  s3,    s1    \n\t  \
    xor.b  t1,    s1    \n\t  \
    xor.b  t0,    s3    \n\t  \
    xor.b  s3,    s0    \n\t  \
    and.b  s1,    s3    \n\t  \
    xor.b  s2,    s3    \n\t  \
    bis.b  s0,    s2    \n\t  \
    xor.b  s1,    s2    \n\t  \
    xor.b  t0,    s1    \n\t

#define enc_round(s0, s1, s2, s3, t0, t1) \
    xor    @r14+, r4    \n\t \
    xor    @r14+, r5    \n\t \
    xor    @r14+, r6    \n\t \
    xor    @r14+, r7    \n\t \
    sbox(s0, s1, s2, s3, t0, t1)\
    rla    r5           \n\t \
    adc    r5           \n\t \
    bit    ONE,   r6    \n\t \
    rrc    r6           \n\t \
    bit    ONE,   r6    \n\t \
    rrc    r6           \n\t \
    bit    ONE,   r6    \n\t \
    rrc    r6           \n\t \
    bit    ONE,   r6    \n\t \
    rrc    r6           \n\t \
    bit    ONE,   r7    \n\t \
    rrc    r7           \n\t \
    bit    ONE,   r7    \n\t \
    rrc    r7           \n\t \
    bit    ONE,   r7    \n\t \
    rrc    r7           \n\t

#define dec_round(s0, s1, s2, s3, t0, t1) \
    xor    @r14+, r4    \n\t \
    xor    @r14+, r5    \n\t \
    xor    @r14+, r6    \n\t \
    xor    @r14+, r7    \n\t \
    sub    r9,    r14   \n\t \
    bit    ONE,   r5    \n\t \
    rrc    r5           \n\t \
    rla    r6           \n\t \
    adc    r6           \n\t \
    rla    r6           \n\t \
    adc    r6           \n\t \
    rla    r6           \n\t \
    adc    r6           \n\t \
    rla    r6           \n\t \
    adc    r6           \n\t \
    rla    r7           \n\t \
    adc    r7           \n\t \
    rla    r7           \n\t \
    adc    r7           \n\t \
    rla    r7           \n\t \
    adc    r7           \n\t \
    invert_sbox(s0, s1, s2, s3, t0, t1)
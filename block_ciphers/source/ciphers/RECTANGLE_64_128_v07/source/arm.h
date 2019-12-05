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

// sbox
#define sbox(s0, s1, s2, s3, t0, t1) \
    orns t0, s3, s1    \n\t \
    eors t0, t0, s0    \n\t \
    bics s0, s0, s1    \n\t \
    eors t1, s2, s3    \n\t \
    eors s0, s0, t1    \n\t \
    eors s3, s1, s2    \n\t \
    eors s1, s2, t0    \n\t \
    ands t1, t0, t1    \n\t \
    eors s3, s3, t1    \n\t \
    orrs s2, s0, s3    \n\t \
    eors s2, s2, t0    \n\t
    
// invert sbox
#define invert_sbox(s0, s1, s2, s3, t0, t1, t2) \
    eors t2, s0, s1    \n\t \
    orrs t0, s0, s3    \n\t \
    eors t0, t0, s2    \n\t \
    eors s2, s1, t0    \n\t \
    ands t1, s0, t0    \n\t \
    eors t1, t1, s3    \n\t \
    eors s1, t1, s2    \n\t \
    orns t1, t0, s1    \n\t \
    eors s3, t2, t1    \n\t \
    orns t1, s3, s1    \n\t \
    eors s0, t0, t1    \n\t
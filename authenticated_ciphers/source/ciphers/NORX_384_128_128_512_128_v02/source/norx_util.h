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

/*
 * NORX reference source code package - reference C implementations
 *
 * Written 2014-2016 by:
 *
 *      - Samuel Neves <sneves@dei.uc.pt>
 *      - Philipp Jovanovic <philipp@jovanovic.io>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
#ifndef NORX_DEFS_H
#define NORX_DEFS_H

/* Workaround for C89 compilers */
#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
#if   defined(_MSC_VER)
#define NORX_INLINE __inline
#elif defined(__GNUC__)
#define NORX_INLINE __inline__
#else
#define NORX_INLINE
#endif
#else
#define NORX_INLINE inline
#endif

#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>

#define STR_(x) #x
#define STR(x) STR_(x)
#define PASTE_(A, B, C) A ## B ## C
#define PASTE(A, B, C) PASTE_(A, B, C)
#define BYTES(x) (((x) + 7) / 8)
#define WORDS(x) (((x) + (NORX_W-1)) / NORX_W)

#define BITS(x) (sizeof(x) * CHAR_BIT)
#define ROTL(x, c) ( ((x) << (c)) | ((x) >> (BITS(x) - (c))) )
#define ROTR(x, c) ( ((x) >> (c)) | ((x) << (BITS(x) - (c))) )

static NORX_INLINE uint32_t load32(const void *in) {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    uint32_t v;
    memcpy(&v, in, sizeof v);
    return v;
#else
    const uint8_t *p = (const uint8_t *)in;
    return ((uint32_t)p[0] << 0) |
            ((uint32_t)p[1] << 8) |
            ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
#endif
}

static NORX_INLINE void store32(void *out, const uint32_t v) {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    memcpy(out, &v, sizeof v);
#else
    uint8_t *p = (uint8_t *)out;
    p[0] = (uint8_t)(v >> 0);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
#endif
}

static void *(*const volatile burn)(void *, int, size_t) = memset;

#endif

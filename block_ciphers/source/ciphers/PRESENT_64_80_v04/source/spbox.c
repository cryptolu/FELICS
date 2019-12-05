/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Dmitry Khovratovich <dmitry.khovratovich@uni.lu>
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

#include "constants.h"


DATA_SP_BOX_DOUBLE_WORD spBox0_lo[16] = { 0x0, 0x1, 0x10000, 0x10001, 0x1, 0x0, 0x10000, 0x1, 0x10001, 0x10000, 0x10001, 0x0, 0x0, 0x10001, 0x1, 0x10000 };

DATA_SP_BOX_DOUBLE_WORD spBox0_hi[16] = { 0x10001, 0x1, 0x1, 0x10000, 0x10000, 0x0, 0x10000, 0x10001, 0x0, 0x10001, 0x10001, 0x10000, 0x1, 0x1, 0x0, 0x0 };

DATA_SP_BOX_DOUBLE_WORD spBox1_lo[16] = { 0x0, 0x2, 0x20000, 0x20002, 0x2, 0x0, 0x20000, 0x2, 0x20002, 0x20000, 0x20002, 0x0, 0x0, 0x20002, 0x2, 0x20000 };

DATA_SP_BOX_DOUBLE_WORD spBox1_hi[16] = { 0x20002, 0x2, 0x2, 0x20000, 0x20000, 0x0, 0x20000, 0x20002, 0x0, 0x20002, 0x20002, 0x20000, 0x2, 0x2, 0x0, 0x0 };

DATA_SP_BOX_DOUBLE_WORD spBox2_lo[16] = { 0x0, 0x4, 0x40000, 0x40004, 0x4, 0x0, 0x40000, 0x4, 0x40004, 0x40000, 0x40004, 0x0, 0x0, 0x40004, 0x4, 0x40000 };

DATA_SP_BOX_DOUBLE_WORD spBox2_hi[16] = { 0x40004, 0x4, 0x4, 0x40000, 0x40000, 0x0, 0x40000, 0x40004, 0x0, 0x40004, 0x40004, 0x40000, 0x4, 0x4, 0x0, 0x0 };

DATA_SP_BOX_DOUBLE_WORD spBox3_lo[16] = { 0x0, 0x8, 0x80000, 0x80008, 0x8, 0x0, 0x80000, 0x8, 0x80008, 0x80000, 0x80008, 0x0, 0x0, 0x80008, 0x8, 0x80000 };

DATA_SP_BOX_DOUBLE_WORD spBox3_hi[16] = { 0x80008, 0x8, 0x8, 0x80000, 0x80000, 0x0, 0x80000, 0x80008, 0x0, 0x80008, 0x80008, 0x80000, 0x8, 0x8, 0x0, 0x0 };

DATA_SP_BOX_DOUBLE_WORD spBox4_lo[16] = { 0x0, 0x10, 0x100000, 0x100010, 0x10, 0x0, 0x100000, 0x10, 0x100010, 0x100000, 0x100010, 0x0, 0x0, 0x100010, 0x10, 0x100000 };

DATA_SP_BOX_DOUBLE_WORD spBox4_hi[16] = { 0x100010, 0x10, 0x10, 0x100000, 0x100000, 0x0, 0x100000, 0x100010, 0x0, 0x100010, 0x100010, 0x100000, 0x10, 0x10, 0x0, 0x0 };

DATA_SP_BOX_DOUBLE_WORD spBox5_lo[16] = { 0x0, 0x20, 0x200000, 0x200020, 0x20, 0x0, 0x200000, 0x20, 0x200020, 0x200000, 0x200020, 0x0, 0x0, 0x200020, 0x20, 0x200000 };

DATA_SP_BOX_DOUBLE_WORD spBox5_hi[16] = { 0x200020, 0x20, 0x20, 0x200000, 0x200000, 0x0, 0x200000, 0x200020, 0x0, 0x200020, 0x200020, 0x200000, 0x20, 0x20, 0x0, 0x0 };

DATA_SP_BOX_DOUBLE_WORD spBox6_lo[16] = { 0x0, 0x40, 0x400000, 0x400040, 0x40, 0x0, 0x400000, 0x40, 0x400040, 0x400000, 0x400040, 0x0, 0x0, 0x400040, 0x40, 0x400000 };

DATA_SP_BOX_DOUBLE_WORD spBox6_hi[16] = { 0x400040, 0x40, 0x40, 0x400000, 0x400000, 0x0, 0x400000, 0x400040, 0x0, 0x400040, 0x400040, 0x400000, 0x40, 0x40, 0x0, 0x0 };

DATA_SP_BOX_DOUBLE_WORD spBox7_lo[16] = { 0x0, 0x80, 0x800000, 0x800080, 0x80, 0x0, 0x800000, 0x80, 0x800080, 0x800000, 0x800080, 0x0, 0x0, 0x800080, 0x80, 0x800000 };

DATA_SP_BOX_DOUBLE_WORD spBox7_hi[16] = { 0x800080, 0x80, 0x80, 0x800000, 0x800000, 0x0, 0x800000, 0x800080, 0x0, 0x800080, 0x800080, 0x800000, 0x80, 0x80, 0x0, 0x0 };

DATA_SP_BOX_DOUBLE_WORD spBox8_lo[16] = { 0x0, 0x100, 0x1000000, 0x1000100, 0x100, 0x0, 0x1000000, 0x100, 0x1000100, 0x1000000, 0x1000100, 0x0, 0x0, 0x1000100, 0x100, 0x1000000 };

DATA_SP_BOX_DOUBLE_WORD spBox8_hi[16] = { 0x1000100, 0x100, 0x100, 0x1000000, 0x1000000, 0x0, 0x1000000, 0x1000100, 0x0, 0x1000100, 0x1000100, 0x1000000, 0x100, 0x100, 0x0, 0x0 };

DATA_SP_BOX_DOUBLE_WORD spBox9_lo[16] = { 0x0, 0x200, 0x2000000, 0x2000200, 0x200, 0x0, 0x2000000, 0x200, 0x2000200, 0x2000000, 0x2000200, 0x0, 0x0, 0x2000200, 0x200, 0x2000000 };

DATA_SP_BOX_DOUBLE_WORD spBox9_hi[16] = { 0x2000200, 0x200, 0x200, 0x2000000, 0x2000000, 0x0, 0x2000000, 0x2000200, 0x0, 0x2000200, 0x2000200, 0x2000000, 0x200, 0x200, 0x0, 0x0 };

DATA_SP_BOX_DOUBLE_WORD spBox10_lo[16] = { 0x0, 0x400, 0x4000000, 0x4000400, 0x400, 0x0, 0x4000000, 0x400, 0x4000400, 0x4000000, 0x4000400, 0x0, 0x0, 0x4000400, 0x400, 0x4000000 };

DATA_SP_BOX_DOUBLE_WORD spBox10_hi[16] = { 0x4000400, 0x400, 0x400, 0x4000000, 0x4000000, 0x0, 0x4000000, 0x4000400, 0x0, 0x4000400, 0x4000400, 0x4000000, 0x400, 0x400, 0x0, 0x0 };

DATA_SP_BOX_DOUBLE_WORD spBox11_lo[16] = { 0x0, 0x800, 0x8000000, 0x8000800, 0x800, 0x0, 0x8000000, 0x800, 0x8000800, 0x8000000, 0x8000800, 0x0, 0x0, 0x8000800, 0x800, 0x8000000 };

DATA_SP_BOX_DOUBLE_WORD spBox11_hi[16] = { 0x8000800, 0x800, 0x800, 0x8000000, 0x8000000, 0x0, 0x8000000, 0x8000800, 0x0, 0x8000800, 0x8000800, 0x8000000, 0x800, 0x800, 0x0, 0x0 };

DATA_SP_BOX_DOUBLE_WORD spBox12_lo[16] = { 0x0, 0x1000, 0x10000000, 0x10001000, 0x1000, 0x0, 0x10000000, 0x1000, 0x10001000, 0x10000000, 0x10001000, 0x0, 0x0, 0x10001000, 0x1000, 0x10000000 };

DATA_SP_BOX_DOUBLE_WORD spBox12_hi[16] = { 0x10001000, 0x1000, 0x1000, 0x10000000, 0x10000000, 0x0, 0x10000000, 0x10001000, 0x0, 0x10001000, 0x10001000, 0x10000000, 0x1000, 0x1000, 0x0, 0x0 };

DATA_SP_BOX_DOUBLE_WORD spBox13_lo[16] = { 0x0, 0x2000, 0x20000000, 0x20002000, 0x2000, 0x0, 0x20000000, 0x2000, 0x20002000, 0x20000000, 0x20002000, 0x0, 0x0, 0x20002000, 0x2000, 0x20000000 };

DATA_SP_BOX_DOUBLE_WORD spBox13_hi[16] = { 0x20002000, 0x2000, 0x2000, 0x20000000, 0x20000000, 0x0, 0x20000000, 0x20002000, 0x0, 0x20002000, 0x20002000, 0x20000000, 0x2000, 0x2000, 0x0, 0x0 };

DATA_SP_BOX_DOUBLE_WORD spBox14_lo[16] = { 0x0, 0x4000, 0x40000000, 0x40004000, 0x4000, 0x0, 0x40000000, 0x4000, 0x40004000, 0x40000000, 0x40004000, 0x0, 0x0, 0x40004000, 0x4000, 0x40000000 };

DATA_SP_BOX_DOUBLE_WORD spBox14_hi[16] = { 0x40004000, 0x4000, 0x4000, 0x40000000, 0x40000000, 0x0, 0x40000000, 0x40004000, 0x0, 0x40004000, 0x40004000, 0x40000000, 0x4000, 0x4000, 0x0, 0x0 };

DATA_SP_BOX_DOUBLE_WORD spBox15_lo[16] = { 0x0, 0x8000, 0x80000000, 0x80008000, 0x8000, 0x0, 0x80000000, 0x8000, 0x80008000, 0x80000000, 0x80008000, 0x0, 0x0, 0x80008000, 0x8000, 0x80000000 };

DATA_SP_BOX_DOUBLE_WORD spBox15_hi[16] = { 0x80008000, 0x8000, 0x8000, 0x80000000, 0x80000000, 0x0, 0x80000000, 0x80008000, 0x0, 0x80008000, 0x80008000, 0x80000000, 0x8000, 0x8000, 0x0, 0x0 };
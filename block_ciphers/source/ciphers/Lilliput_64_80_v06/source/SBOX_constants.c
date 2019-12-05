/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

/****************************************************************************** 
 *
 * Constants used by encryption/decryption
 *
 ******************************************************************************/

#include <stdint.h>
#include "constants.h"


SBOX_BYTE S[16] = {0x04, 0x08, 0x07, 0x01, 0x09, 0x03, 0x02, 0x0e, 0x00, 0x0b, 0x06, 0x0f, 0x0a, 0x05, 0x0d, 0x0c};

	
SBOX_WORD invS16[16][16] = { 
{  1028, 2052, 1796, 260, 2308, 772, 516, 3588, 4, 2820, 1540, 3844, 2564, 1284, 3332, 3076}, 
{  1032, 2056, 1800, 264, 2312, 776, 520, 3592, 8, 2824, 1544, 3848, 2568, 1288, 3336, 3080}, 
{  1031, 2055, 1799, 263, 2311, 775, 519, 3591, 7, 2823, 1543, 3847, 2567, 1287, 3335, 3079}, 
{  1025, 2049, 1793, 257, 2305, 769, 513, 3585, 1, 2817, 1537, 3841, 2561, 1281, 3329, 3073}, 
{  1033, 2057, 1801, 265, 2313, 777, 521, 3593, 9, 2825, 1545, 3849, 2569, 1289, 3337, 3081}, 
{  1027, 2051, 1795, 259, 2307, 771, 515, 3587, 3, 2819, 1539, 3843, 2563, 1283, 3331, 3075}, 
{  1026, 2050, 1794, 258, 2306, 770, 514, 3586, 2, 2818, 1538, 3842, 2562, 1282, 3330, 3074}, 
{  1038, 2062, 1806, 270, 2318, 782, 526, 3598, 14, 2830, 1550, 3854, 2574, 1294, 3342, 3086}, 
{  1024, 2048, 1792, 256, 2304, 768, 512, 3584, 0, 2816, 1536, 3840, 2560, 1280, 3328, 3072}, 
{  1035, 2059, 1803, 267, 2315, 779, 523, 3595, 11, 2827, 1547, 3851, 2571, 1291, 3339, 3083}, 
{  1030, 2054, 1798, 262, 2310, 774, 518, 3590, 6, 2822, 1542, 3846, 2566, 1286, 3334, 3078}, 
{  1039, 2063, 1807, 271, 2319, 783, 527, 3599, 15, 2831, 1551, 3855, 2575, 1295, 3343, 3087}, 
{  1034, 2058, 1802, 266, 2314, 778, 522, 3594, 10, 2826, 1546, 3850, 2570, 1290, 3338, 3082}, 
{  1029, 2053, 1797, 261, 2309, 773, 517, 3589, 5, 2821, 1541, 3845, 2565, 1285, 3333, 3077}, 
{  1037, 2061, 1805, 269, 2317, 781, 525, 3597, 13, 2829, 1549, 3853, 2573, 1293, 3341, 3085}, 
{  1036, 2060, 1804, 268, 2316, 780, 524, 3596, 12, 2828, 1548, 3852, 2572, 1292, 3340, 3084}
};



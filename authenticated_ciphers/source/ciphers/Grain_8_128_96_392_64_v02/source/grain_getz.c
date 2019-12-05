/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 8-bit AVR ATMega 128, Fast speed code (C+ASM)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include "grain_common.h"

static const uint8_t deinterleave[256] = 
{
	0x00, 0x01, 0x10, 0x11, 0x02, 0x03, 0x12, 0x13, 0x20, 0x21, 0x30, 0x31, 0x22, 0x23, 0x32, 0x33, 
	0x04, 0x05, 0x14, 0x15, 0x06, 0x07, 0x16, 0x17, 0x24, 0x25, 0x34, 0x35, 0x26, 0x27, 0x36, 0x37, 
	0x40, 0x41, 0x50, 0x51, 0x42, 0x43, 0x52, 0x53, 0x60, 0x61, 0x70, 0x71, 0x62, 0x63, 0x72, 0x73, 
	0x44, 0x45, 0x54, 0x55, 0x46, 0x47, 0x56, 0x57, 0x64, 0x65, 0x74, 0x75, 0x66, 0x67, 0x76, 0x77, 
	0x08, 0x09, 0x18, 0x19, 0x0a, 0x0b, 0x1a, 0x1b, 0x28, 0x29, 0x38, 0x39, 0x2a, 0x2b, 0x3a, 0x3b,
	0x0c, 0x0d, 0x1c, 0x1d, 0x0e, 0x0f, 0x1e, 0x1f, 0x2c, 0x2d, 0x3c, 0x3d, 0x2e, 0x2f, 0x3e, 0x3f, 
	0x48, 0x49, 0x58, 0x59, 0x4a, 0x4b, 0x5a, 0x5b, 0x68, 0x69, 0x78, 0x79, 0x6a, 0x6b, 0x7a, 0x7b, 
	0x4c, 0x4d, 0x5c, 0x5d, 0x4e, 0x4f, 0x5e, 0x5f, 0x6c, 0x6d, 0x7c, 0x7d, 0x6e, 0x6f, 0x7e, 0x7f, 
	0x80, 0x81, 0x90, 0x91, 0x82, 0x83, 0x92, 0x93, 0xa0, 0xa1, 0xb0, 0xb1, 0xa2, 0xa3, 0xb2, 0xb3, 
	0x84, 0x85, 0x94, 0x95, 0x86, 0x87, 0x96, 0x97, 0xa4, 0xa5, 0xb4, 0xb5, 0xa6, 0xa7, 0xb6, 0xb7,
	0xc0, 0xc1, 0xd0, 0xd1, 0xc2, 0xc3, 0xd2, 0xd3, 0xe0, 0xe1, 0xf0, 0xf1, 0xe2, 0xe3, 0xf2, 0xf3, 
	0xc4, 0xc5, 0xd4, 0xd5, 0xc6, 0xc7, 0xd6, 0xd7, 0xe4, 0xe5, 0xf4, 0xf5, 0xe6, 0xe7, 0xf6, 0xf7, 
	0x88, 0x89, 0x98, 0x99, 0x8a, 0x8b, 0x9a, 0x9b, 0xa8, 0xa9, 0xb8, 0xb9, 0xaa, 0xab, 0xba, 0xbb, 
	0x8c, 0x8d, 0x9c, 0x9d, 0x8e, 0x8f, 0x9e, 0x9f, 0xac, 0xad, 0xbc, 0xbd, 0xae, 0xaf, 0xbe, 0xbf, 
	0xc8, 0xc9, 0xd8, 0xd9, 0xca, 0xcb, 0xda, 0xdb, 0xe8, 0xe9, 0xf8, 0xf9, 0xea, 0xeb, 0xfa, 0xfb,
	0xcc, 0xcd, 0xdc, 0xdd, 0xce, 0xcf, 0xde, 0xdf, 0xec, 0xed, 0xfc, 0xfd, 0xee, 0xef, 0xfe, 0xff
};

uint8_t grain_getz(GrainState * g)
{	uint8_t r0 = deinterleave[grain_update(g)];
	uint8_t r1 = SWAP(deinterleave[grain_update(g)]);
	uint8_t t = (r0 ^ r1) & 0xf0;
	g->z1 = SWAP(r1 ^ t);
	return r0 ^ t;
}
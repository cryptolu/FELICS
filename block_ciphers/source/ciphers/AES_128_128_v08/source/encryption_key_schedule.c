/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Dmitry Khovratovich <dmitry.khovratovich@uni.lu> and
 * André Stemper <andre.stemper@uni.lu>
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

/* Copyright (C) 2003,2006 B. Poettering
 *
 * This program is free software; you can redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version. Whenever you redistribute a copy
 * of this document, make sure to include the copyright and license
 * agreement without modification.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * The license text can be found here: http://www.gnu.org/licenses/gpl.txt

 *                http://point-at-infinity.org/avraes/
 *
 * This AES implementation was written in May 2003 by B. Poettering. It is
 * published under the terms of the GNU General Public License. If you need
 * AES code, but this license is unsuitable for your project, feel free to
 * contact me: avraes AT point-at-infinity.org
 */

#ifdef AVR
#include "constants.h"
/*----------------------------------------------------------------------------*/
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys) {
	asm volatile (
	/*****************************************************************************/
	/*KEY_EXPAND                                                                 */
	/*The following routine implements the Rijndael key expansion algorithm. The */
	/*caller supplies the 128 bit key in the registers ST11-ST44 and a pointer   */
	/*in the YH:YL register pair. The key is expanded to the memory              */
	/*positions [Y : Y+16*11-1]. Note: the key expansion is necessary for both   */
	/*encryption and decryption.                                                 */
	/*                                                                           */
	/*Parameters:                                                                */
	/*    ST11-ST44:   the 128 bit key                                           */
	/*        YH:YL:   pointer to ram location                                   */
	/*Touched registers:                                                         */
	/*    ST11-ST44,H1-H3,ZH,ZL,YH,YL                                            */
	/*Clock cycles:    756                                                       */
	/*****************************************************************************/
	 /*--------------------------------------------------*/
	 /* Store all modified registers                     */
	 /*--------------------------------------------------*/
			"push   r0;                 \n"
			"push   r1;                 \n"
			"push   r2;                 \n"
			"push   r3;                 \n"
			"push   r4;                 \n"
			"push   r5;                 \n"
			"push   r6;                 \n"
			"push   r7;                 \n"
			"push   r8;                 \n"
			"push   r9;                 \n"
			"push   r10;                \n"
			"push   r11;                \n"
			"push   r12;                \n"
			"push   r13;                \n"
			"push   r14;                \n"
			"push   r15;                \n"
			"push   r16;                \n"
			"push   r17;                \n"
			"push   r18;                \n"
			"push   r19;                \n"
			"push   r20;                \n"
            "push   r21;                \n"
	 /*--------------------------------------------------*/
	 /* Load key to r0-r15                               */
	 /*--------------------------------------------------*/
			"ld r0, x+;                 \n"
			"ld r1, x+;                 \n"
			"ld r2, x+;                 \n"
			"ld r3, x+;                 \n"
			"ld r4, x+;                 \n"
			"ld r5, x+;                 \n"
			"ld r6, x+;                 \n"
			"ld r7, x+;                 \n"
			"ld r8, x+;                 \n"
			"ld r9, x+;                 \n"
			"ld r10, x+;                \n"
			"ld r11, x+;                \n"
			"ld r12, x+;                \n"
            "ld r13, x+;                \n"
            "ld r14, x+;                \n"
            "ld r15, x+;                \n"
			/*original assembler snippet */
			"key_expand:                \n"
			"ldi r16, 1                 \n"
			"ldi r17, 0x1b              \n"
			"ldi ZH, hi8(sbox)          \n"
			"rjmp keyexp1               \n"
			"keyexp0:mov ZL, r13        \n"
			"lpm r18, Z                 \n"
			"eor r0, r18                \n"
			"eor r0, r16                \n"
			"mov ZL, r14                \n"
			"lpm r18, Z                 \n"
			"eor r1, r18                \n"
			"mov ZL, r15                \n"
			"lpm r18, Z                 \n"
			"eor r2, r18                \n"
			"mov ZL, r12                \n"
			"lpm r18, Z                 \n"
			"eor r3, r18                \n"
			"eor r4, r0                 \n"
			"eor r5, r1                 \n"
			"eor r6, r2                 \n"
			"eor r7, r3                 \n"
			"eor r8, r4                 \n"
			"eor r9, r5                 \n"
			"eor r10, r6                \n"
			"eor r11, r7                \n"
			"eor r12, r8                \n"
			"eor r13, r9                \n"
			"eor r14, r10               \n"
			"eor r15, r11               \n"
			"lsl r16                    \n"
			"brcc keyexp1               \n"
			"eor r16, r17               \n"
			"keyexp1:st Y+, r0          \n"
			"st Y+, r1                  \n"
			"st Y+, r2                  \n"
			"st Y+, r3                  \n"
			"st Y+, r4                  \n"
			"st Y+, r5                  \n"
			"st Y+, r6                  \n"
			"st Y+, r7                  \n"
			"st Y+, r8                  \n"
			"st Y+, r9                  \n"
			"st Y+, r10                 \n"
			"st Y+, r11                 \n"
			"st Y+, r12                 \n"
			"st Y+, r13                 \n"
			"st Y+, r14                 \n"
			"st Y+, r15                 \n"
			"cpi r16, 0x6c              \n"
            "brne keyexp0               \n"
	  /*--------------------------------------------------*/
			/* Restore registers                                */
	  /*--------------------------------------------------*/
			"pop r21                    \n"
			"pop r20                    \n"
			"pop r19                    \n"
			"pop r18                    \n"
			"pop r17                    \n"
			"pop r16                    \n"
			"pop r15                    \n"
			"pop r14                    \n"
			"pop r13                    \n"
			"pop r12                    \n"
			"pop r11                    \n"
			"pop r10                    \n"
			"pop r9                     \n"
			"pop r8                     \n"
			"pop r7                     \n"
			"pop r6                     \n"
			"pop r5                     \n"
			"pop r4                     \n"
			"pop r3                     \n"
			"pop r2                     \n"
			"pop r1                     \n"
			"pop r0                     \n"
            ::[key] "x"(key),[roundKeys] "y"(roundKeys),
			[sbox] ""(sbox)
			);

}
#endif

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

#include <stdint.h>

#include "cipher.h"
#include "constants.h"


void RunDecryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    RunEncryptionKeySchedule(key, roundKeys);
      /*****************************************************************************/
      /*                                                                           */
      /*PATCH_DECRYPTION_KEY                                                       */
      /*The following routine applies the MixColumns diffusion operator to the     */
      /*columns of the expanded key (to be precise:	to all but the first and       */
      /*last four). This is necessary, as the decryption routine below implements  */
      /*the so-called "equivalent decryption algorithm" of Rijndael.The original   */
      /*key material is overwritten by the patched one.                            */
      /*Note: this routine is only needed for decryption purposes!                 */
      /*                                                                           */
      /*Parameters:                                                                */
      /*        YH:YL:	pointer to expanded key                                    */
      /*Touched registers:                                                         */
      /*    ST11-ST41,H1-H5,I,ZH,ZL,YH,YL                                          */
      /*Clock cycles:	4221                                                       */
      /*                                                                           */
      /*****************************************************************************/
      asm volatile (\
      /*--------------------------------------------------*/
      /* Store all modified registers                     */
      /*--------------------------------------------------*/
      "push   r0;                  \n"
      "push   r1;                  \n"
      "push   r2;                  \n"
      "push   r3;                  \n"
      "push   r4;                  \n"
      "push   r5;                  \n"
      "push   r6;                  \n"
      "push   r7;                  \n"
      "push   r8;                  \n"
      "push   r9;                  \n"
      "push   r10;                 \n"
      "push   r11;                 \n"
      "push   r12;                 \n"
      "push   r13;                 \n"
      "push   r14;                 \n"
      "push   r15;                 \n"
      "push   r16;                 \n"
      "push   r17;                 \n"
      "push   r18;                 \n"
      "push   r19;                 \n"
      "push   r20;                 \n"
      "push   r21;                 \n"
      //#if 0

       /*original assembler snippet*/
      "patch_decryption_key: ;     \n"
      /*"  adiw YH:YL, 16 ;        \n"*/
      "  adiw YL, 16 ;             \n"
      "  ldi r21, 35 ;             \n"
      "patchd0:ldd r0, Y+0 ;       \n"
      "  ldd r1, Y+1 ;             \n"
      "  ldd r2, Y+2 ;             \n"
      "  ldd r3, Y+3 ;             \n"
      "  ldi ZH, hi8(sbox) ;       \n"
      "  mov ZL, r0 ;              \n"
      "  lpm ZL, Z ;               \n"
      "  ldi ZH, hi8(isbox0e) ;    \n"
      "  lpm r16, Z ;              \n"
      "  ldi ZH, hi8(isbox09) ;    \n"
      "  lpm r17, Z ;              \n"
      "  ldi ZH, hi8(isbox0d) ;    \n"
      "  lpm r18, Z ;              \n"
      "  ldi ZH, hi8(isbox0b) ;    \n"
      "  lpm r19, Z ;              \n"
      "  ldi ZH, hi8(sbox) ;       \n"
      "  mov ZL, r1 ;              \n"
      "  lpm ZL, Z ;               \n"
      "  ldi ZH, hi8(isbox0b) ;    \n"
      "  lpm r20, Z ;              \n"
      "  eor r16, r20 ;            \n"
      "  ldi ZH, hi8(isbox0e) ;    \n"
      "  lpm r20, Z ;              \n"
      "  eor r17, r20 ;            \n"
      "  ldi ZH, hi8(isbox09) ;    \n"
      "  lpm r20, Z ;              \n"
      "  eor r18, r20 ;            \n"
      "  ldi ZH, hi8(isbox0d) ;    \n"
      "  lpm r20, Z ;              \n"
      "  eor r19, r20 ;            \n"
      "  ldi ZH, hi8(sbox) ;       \n"
      "  mov ZL, r2 ;              \n"
      "  lpm ZL, Z ;               \n"
      "  ldi ZH, hi8(isbox0d) ;    \n"
      "  lpm r20, Z ;              \n"
      "  eor r16, r20 ;            \n"
      "  ldi ZH, hi8(isbox0b) ;    \n"
      "  lpm r20, Z ;              \n"
      "  eor r17, r20 ;            \n"
      "  ldi ZH, hi8(isbox0e) ;    \n"
      "  lpm r20, Z ;              \n"
      "  eor r18, r20 ;            \n"
      "  ldi ZH, hi8(isbox09) ;    \n"
      "  lpm r20, Z ;              \n"
      "  eor r19, r20 ;            \n"
      "  ldi ZH, hi8(sbox) ;       \n"
      "  mov ZL, r3 ;              \n"
      "  lpm ZL, Z ;               \n"
      "  ldi ZH, hi8(isbox09) ;    \n"
      "  lpm r20, Z ;              \n"
      "  eor r16, r20 ;            \n"
      "  ldi ZH, hi8(isbox0d) ;    \n"
      "  lpm r20, Z ;              \n"
      "  eor r17, r20 ;            \n"
      "  ldi ZH, hi8(isbox0b) ;    \n"
      "  lpm r20, Z ;              \n"
      "  eor r18, r20 ;            \n"
      "  ldi ZH, hi8(isbox0e) ;    \n"
      "  lpm r20, Z ;              \n"
      "  eor r19, r20 ;            \n"
      "  st Y+, r16 ;              \n"
      "  st Y+, r17 ;              \n"
      "  st Y+, r18 ;              \n"
      "  st Y+, r19 ;              \n"
      "  dec r21 ;                 \n"
      "  sbrs r21, 7 ;             \n"
      "  jmp patchd0 ;             \n"
    //  #endif
      /*--------------------------------------------------*/
      /* Restore registers                                */
      /*--------------------------------------------------*/
      "pop   r21 ;               \n"
      "pop   r20 ;               \n"
      "pop   r19 ;               \n"
      "pop   r18 ;               \n"
      "pop   r17 ;               \n"
      "pop   r16 ;               \n"
      "pop   r15 ;               \n"
      "pop   r14 ;               \n"
      "pop   r13 ;               \n"
      "pop   r12 ;               \n"
      "pop   r11 ;               \n"
      "pop   r10 ;               \n"
      "pop   r9  ;               \n"
      "pop   r8  ;               \n"
      "pop   r7  ;               \n"
      "pop   r6  ;               \n"
      "pop   r5  ;               \n"
      "pop   r4  ;               \n"
      "pop   r3  ;               \n"
      "pop   r2  ;               \n"
      "pop   r1  ;               \n"
      "pop   r0  ;               \n"
  :
  : [roundKeys] "y" (roundKeys), [sbox] "" (sbox), [isbox0e] "" (isbox0e), [isbox09] "" (isbox09), [isbox0d] "" (isbox0d), [isbox0b] "" (isbox0b)
    );
}

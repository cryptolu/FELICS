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
#include <string.h>

#include "cipher.h"
#include "constants.h"




#define permTab(newTab, tab, roundx8) \
{\
	newTab[0] = tab[roundx8 + 7];\
  	newTab[1] = tab[roundx8 + 6];\
  	newTab[2] = tab[roundx8 + 5];\
  	newTab[3] = tab[roundx8 + 4];\
  	newTab[4] = tab[roundx8 + 3];\
  	newTab[5] = tab[roundx8 + 2];\
  	newTab[6] = tab[roundx8 + 1];\
  	newTab[7] = tab[roundx8 + 0];\
}

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	
  uint8_t i;
  uint8_t tmpblock[16];
  memcpy(tmpblock, block, 16);
  
  /*29 rounds */
  for(i = 0 ; i < 29 ; i++)
  {
    uint8_t tmproundKeysi[8];

  	uint8_t roundx8 = i*8;
  	permTab(tmproundKeysi, roundKeys, roundx8);
  	
    uint32_t *tmpblock32 = (uint32_t *)(void *)tmpblock;
    uint32_t *tmproundKeysi32 = (uint32_t *)(void *)tmproundKeysi;
    /* NonLinearLayer + LinearLayer */
    uint8_t tmp[8] ;
    ((uint32_t *)(void *)tmp)[0] = tmpblock32[0] ^ READ_ROUND_KEY_DOUBLE_WORD(tmproundKeysi32[0]) ;
    ((uint32_t *)(void *)tmp)[1] = tmpblock32[1] ^ READ_ROUND_KEY_DOUBLE_WORD(tmproundKeysi32[1]) ;
    
    uint8_t tmpblock7[4] = {tmpblock[7], tmpblock[7], tmpblock[7], tmpblock[7]};
    uint32_t *TmpBlock7 = (uint32_t *)(void *)tmpblock7;
    
    uint16_t TmpBlock[4];
    
    
    TmpBlock[0] = (READ_SBOX_WORD( invS16[ tmp[7] ][ tmp[6] ]) );
    TmpBlock[1] = (READ_SBOX_WORD( invS16[ tmp[5] ][ tmp[4] ]) ) ;
    ((uint32_t *)(void *)tmpblock)[2] ^= ((uint32_t *)(void *)TmpBlock)[0] ^ (TmpBlock7[0] <<8);
    TmpBlock[2] = (READ_SBOX_WORD( invS16[ tmp[3] ][ tmp[2] ]) ) ;
    TmpBlock[3] = (READ_SBOX_WORD( invS16[ tmp[1] ][ tmp[0] ]) ) ;
    ((uint32_t *)(void *)tmpblock)[3] ^= ((uint32_t *)(void *)TmpBlock)[1] ^ TmpBlock7[0];
    tmpblock[15] ^= tmpblock[6] ^ tmpblock[5] ^ tmpblock[4] ^ tmpblock[3] ^ tmpblock[2] ^ tmpblock[1];
    
    
    /* PermutationLayer */

    /*Avoid useless operation in the for loops and create as many temp as necessary, use all the temp at the end */
    uint8_t temp13 = tmpblock[13];
	tmpblock[13] = tmpblock[0];
	uint8_t temp9 = tmpblock[9];
	tmpblock[9] = tmpblock[1];
	uint8_t temp14 = tmpblock[14];
	tmpblock[14] = tmpblock[2];
	uint8_t temp8 = tmpblock[8];
	tmpblock[8] = tmpblock[3];
	uint8_t temp10 = tmpblock[10];
	tmpblock[10] = tmpblock[4];
	uint8_t temp11 = tmpblock[11];
	tmpblock[11] = tmpblock[5];
	uint8_t temp12 = tmpblock[12];
	tmpblock[12] = tmpblock[6];
	uint8_t temp15 = tmpblock[15];
	tmpblock[15] = tmpblock[7];
	
	tmpblock[4] = temp8;
	tmpblock[5] = temp9;
	tmpblock[3] = temp10;
	tmpblock[1] = temp11;
	tmpblock[2] = temp12;
	tmpblock[6] = temp13;
	tmpblock[0] = temp14;
	tmpblock[7] = temp15;
	
  } /* end round */
  
  
  /* last round */
    

  uint8_t tmproundKeysi[8];
	permTab(tmproundKeysi, roundKeys, 232);

	uint32_t *tmpblock32 = (uint32_t *)(void *)tmpblock;
	uint32_t *tmproundKeysi32 = (uint32_t *)(void *)tmproundKeysi;
	/* NonLinearLayer + LinearLayer */
	uint8_t tmp[8];
	((uint32_t *)(void *)tmp)[0] = tmpblock32[0] ^ READ_ROUND_KEY_DOUBLE_WORD(tmproundKeysi32[0]) ;
	((uint32_t *)(void *)tmp)[1] = tmpblock32[1] ^ READ_ROUND_KEY_DOUBLE_WORD(tmproundKeysi32[1]) ;

	uint8_t tmpblock7[4] = {tmpblock[7], tmpblock[7], tmpblock[7], tmpblock[7]};
	uint32_t *TmpBlock7 = (uint32_t *)(void *)tmpblock7;

	uint16_t TmpBlock[4];


	TmpBlock[0] = (READ_SBOX_WORD( invS16[ tmp[7] ][ tmp[6] ]) );
	TmpBlock[1] = (READ_SBOX_WORD( invS16[ tmp[5] ][ tmp[4] ]) ) ;
	((uint32_t *)(void *)tmpblock)[2] ^= ((uint32_t *)(void *)TmpBlock)[0] ^ (TmpBlock7[0] <<8);
	TmpBlock[2] = (READ_SBOX_WORD( invS16[ tmp[3] ][ tmp[2] ]) ) ;
	TmpBlock[3] = (READ_SBOX_WORD( invS16[ tmp[1] ][ tmp[0] ]) ) ;
	((uint32_t *)(void *)tmpblock)[3] ^= ((uint32_t *)(void *)TmpBlock)[1] ^ TmpBlock7[0];
	tmpblock[15] ^= tmpblock[6] ^ tmpblock[5] ^ tmpblock[4] ^ tmpblock[3] ^ tmpblock[2] ^ tmpblock[1];
  
  memcpy(block, tmpblock, 16);
	
}


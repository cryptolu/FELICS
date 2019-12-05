/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2017 University of Luxembourg
 *
 * Written in 2019 by Luan Cardoso dos Santos <luan.cardoso@uni.lu> <luancardoso@icloud.com>
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
#include "util.h"
#include "sparkle_opt.h"
#include "stdint.h"
#include "string.h" //for memcpy
//                                               vNULL   vNULL
inline static void decryptCT(uint32_t *state, u8 *M, u64 *Mlen,  u8 *c, u64 clen  /*const unsigned char *k*/){
    //clen -= CRYPTO_ABYTES;
    //*mlen = clen;
    uint8_t m[BYTE(RATE)];
    if (clen != 0){
        //main decryption loop
        while (clen > BYTE(RATE)){
            //$M_j \leftarrow p^\prime_2 (S_L, C_j)$
            for(int i=0; i<BYTE(RATE); i++)
                m[i]=c[i];
            rho2((uint32_t*)(m), state);
            //$S_L \parallel S_R \leftarrow \text{SparkleRATE}_{slim}(\rho^\prime_1(S_L, C_j) \parallel S_R)$
            rhop1(state, (uint32_t*)(c));
            RATEWHITENING(state);
            sparklePermutation(state, STEPSSLIM);
            //Move pointers
            clen -= BYTE(RATE);
            //m += BYTE(RATE);
            memcpy(c, m, BYTE(RATE));
            c += BYTE(RATE);
        }
        //decrypt last block
        uint32_t lBlock[WORD(RATE)];
        pad(lBlock, (u8 *)(c), clen);
        rho2(lBlock, state);
        memcpy(m, lBlock, clen);
        //Finalization
        if (clen < BYTE(RATE)){
            pad(lBlock, m, clen);
            rho1(state, lBlock);
            INJECTCONST(state, PADPTCONST);
            RATEWHITENING(state);
            sparklePermutation(state, STEPSBIG);
        }
        else {
            rhop1(state, (uint32_t *)(c));
            INJECTCONST(state, NOPADPTCONST);
            RATEWHITENING(state);
            sparklePermutation(state, STEPSBIG);
        }
        memcpy(c, m, clen);
    }
    /*
    c+=clen; //move c to point to tag.

    for(int i=0; i<CRYPTO_ABYTES; i++){ //xor key to tag location on state
        ((uint8_t *)(state) + BYTE(RATE) )[i] ^= k[i];
    }

    if (verifyTag(state, (u8 *)(c)) == 0)
        return 0;
    else{
        #ifndef _DEBUG
            //Zero generated plaintext in case of failure to authenticate
            for (unsigned long long i=0; i < *mlen; i++) m[i]=0;
        #endif
        return -1;
    }
    */
}
/*AKA decrypt*/
void ProcessCiphertext(uint8_t *state, uint8_t *message, uint32_t message_length)
{
    /* Add ciphertext processing code here */
    decryptCT((uint32_t*)(state), NULL, NULL, message, message_length);

}

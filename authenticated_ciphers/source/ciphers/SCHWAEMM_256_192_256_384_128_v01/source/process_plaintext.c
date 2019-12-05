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

#include "cipher.h"
#include "constants.h"
#include "util.h"
#include "sparkle_opt.h"
#include "stdint.h"
#include "string.h" //for memcpy

inline static void  encryptPT(uint32_t *state, u8 *C, u64 *Clen, u8 *m, u64 mlen /*const unsigned char *k*/){
    //*clen = mlen + CRYPTO_ABYTES;
    if (mlen != 0){
        uint8_t c[BYTE(RATE)];
        int constM = (mlen % BYTE(RATE) != 0) ? PADPTCONST : NOPADPTCONST;

        /*main encryption loop*/
        while (mlen > BYTE(RATE)){
            // $C_j \leftarrpow$C_j \leftarrow \rho_2(S_L , M_j)$
            memcpy(c, m, BYTE(RATE));
            rho2((uint32_t *)(c), state);
            // $S_L \parallel S_r \leftarrow \text{SparkleRATE}_{slim} (\rho_1 (S_L, M_j) \parallel S_R)$
            rho1(state, (uint32_t *)(m));
            RATEWHITENING(state);
            sparklePermutation(state, STEPSSLIM);
/**/            memcpy(m, c, BYTE(RATE)); //write back for implace encryption
            m += BYTE(RATE);
            //c += BYTE(RATE);
            mlen -= BYTE(RATE);
        }
        //pad last block
        uint32_t lBlock[WORD(RATE)];
        pad(lBlock, (u8 *)(m), mlen);

        //process last lBlock
        // $C_{\ell_{M-1}} \leftarrow \text{trunc}_t(\rho_2(S_L, M_{\ell_{M-1}}))$
        rho2(lBlock, state);
        memcpy(c, lBlock, mlen);
        // $S_L \parallel S_R \leftarrow \text{SparkleRATE}_{big}(\rho_1 (S_L, M_{\ell_{M-1}}) \parallel S_R \oplus \text{Const}_M))$
        pad(lBlock, (u8 *)(m), mlen);
        rho1(state, lBlock);
        INJECTCONST(state, constM);
        RATEWHITENING(state);
        sparklePermutation(state, STEPSBIG);
        memcpy(m, c, mlen);
    }
    /*
        //write tag to ciphertext
        memcpy(c+mlen, (u8*)(state)+BYTE(RATE), CRYPTO_ABYTES);

        for(int i=0; i<CRYPTO_ABYTES; i++){
            (c+mlen)[i] ^= k[i];
        }
    */
}


/*AKA encrypt*/
void ProcessPlaintext(uint8_t *state, uint8_t *message, uint32_t message_length)
{
    encryptPT((uint32_t*)(state), NULL, NULL, message, (uint64_t)(message_length) );
    /* Add plaintext processing code here */
}

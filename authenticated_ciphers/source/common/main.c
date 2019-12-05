/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015-2019 University of Luxembourg
 *
 * Author: Luan Cardoso (2019), Virat Shejwalkar (2017),
 *         Daniel Dinu (2015), and Yann Le Corre (2015)
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
#include "common.h"
#include "constants.h"

#if defined(PC) && defined(MEASURE_CYCLE_COUNT) && \
    (MEASURE_CYCLE_COUNT_ENABLED == MEASURE_CYCLE_COUNT)
#include <stdio.h>
#include <inttypes.h>
#include "cycleCount.h"
#endif /* PC & MEASURE_CYCLE_COUNT */

#if defined(ARM) && defined(MEASURE_CYCLE_COUNT) && \
    (MEASURE_CYCLE_COUNT_ENABLED == MEASURE_CYCLE_COUNT)
#include <sam3x8e.h>
#include <stdio.h>
#include <unistd.h>
#include "cycleCount.h"
#endif /* ARM & MEASURE_CYCLE_COUNT */

#if defined(ARM) && defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
#include <stdio.h>
#endif /* ARM & DEBUG */

#ifndef SKIP_STATE_CHECK_INI
#define SKIP_STATE_CHECK_INI SKIP_STATE_CHECK_FALSE
#endif

#ifndef SKIP_STATE_CHECK_PAD
#define SKIP_STATE_CHECK_PAD SKIP_STATE_CHECK_FALSE
#endif

#ifndef SKIP_STATE_CHECK_PPD
#define SKIP_STATE_CHECK_PPD SKIP_STATE_CHECK_FALSE
#endif

#ifndef SKIP_STATE_CHECK_FIN
#define SKIP_STATE_CHECK_FIN SKIP_STATE_CHECK_FALSE
#endif

#ifndef SKIP_STATE_CHECK_PCD
#define SKIP_STATE_CHECK_PCD SKIP_STATE_CHECK_FALSE
#endif

/*
 *
 * Entry point into program
 *
 */
int main() {
    RAM_DATA_BYTE key[KEY_SIZE];

    RAM_DATA_BYTE nonce[NONCE_SIZE];

    RAM_DATA_BYTE state[STATE_SIZE] = { 0 };

#if defined(MESSAGE_SIZE) && (0 != MESSAGE_SIZE)
    RAM_DATA_BYTE message[MESSAGE_SIZE];
#else
    RAM_DATA_BYTE *message;
#endif /* (MESSAGE_SIZE) && (0 != MESSAGE_SIZE) */


#if defined(ASSOCIATED_DATA_SIZE) && (0 != ASSOCIATED_DATA_SIZE)
    RAM_DATA_BYTE associatedData[ASSOCIATED_DATA_SIZE];
#else
    RAM_DATA_BYTE *associatedData;
#endif /* (ASSOCIATED_DATA_SIZE) && (0 != ASSOCIATED_DATA_SIZE) */


    /* No authentication tag in scenario 1 and 4 */
#if defined(SCENARIO) && ((SCENARIO_1 != SCENARIO) || (SCENARIO_4 != SCENARIO))
    RAM_DATA_BYTE tag[TAG_SIZE] = { 0 };
#endif


    InitializeDevice();

    InitializeKey(key);

    InitializeNonce(nonce);


#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)


    InitializePlaintext(message);
    InitializeAssociatedDataBlock(associatedData);
#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayData(state, STATE_SIZE, STATE_NAME);
#endif
#if defined(DEBUG) && (DEBUG_MEDIUM == (DEBUG_MEDIUM & DEBUG))
    DisplayVerifyData(key, KEY_SIZE, KEY_NAME);
    DisplayVerifyData(nonce, NONCE_SIZE, NONCE_NAME);
    DisplayVerifyData(associatedData, ASSOCIATED_DATA_SIZE,
            ASSOCIATED_DATA_NAME);
#endif
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    DisplayVerifyData(message, MESSAGE_SIZE, PLAINTEXT_NAME);
#endif


#else /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


    InitializeMessage(message, MESSAGE_SIZE);
    InitializeAssociatedData(associatedData, ASSOCIATED_DATA_SIZE);
#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayData(state, STATE_SIZE, STATE_NAME);
#endif
#if defined(DEBUG) && (DEBUG_MEDIUM == (DEBUG_MEDIUM & DEBUG))
    DisplayData(key, KEY_SIZE, KEY_NAME);
    DisplayData(nonce, NONCE_SIZE, NONCE_NAME);
    DisplayData(associatedData, ASSOCIATED_DATA_SIZE, ASSOCIATED_DATA_NAME);
#endif
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    DisplayData(message, MESSAGE_SIZE, PLAINTEXT_NAME);
#endif


#endif /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


    BEGIN_ENCRYPTION_INITIALIZATION();
    Initialize(state, key, nonce);
    END_ENCRYPTION_INITIALIZATION();


#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)


#if (SKIP_STATE_CHECK_FALSE == SKIP_STATE_CHECK_INI) && defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayVerifyData(state, STATE_SIZE, POST_INTIALIZATION_STATE_NAME);
#endif


#else /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayData(state, STATE_SIZE, POST_INTIALIZATION_STATE_NAME);
#endif


#endif /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


    BEGIN_ENCRYPTION_ASSOCIATED_DATA_PROCESSING();
    ProcessAssociatedData(state, associatedData, ASSOCIATED_DATA_SIZE);
    END_ENCRYPTION_ASSOCIATED_DATA_PROCESSING();


#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)


#if (SKIP_STATE_CHECK_FALSE == SKIP_STATE_CHECK_PAD) && defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayVerifyData(state, STATE_SIZE,
            POST_ASSOCIATED_DATA_PROCESSING_STATE_NAME);
#endif


#else /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayData(state, STATE_SIZE, POST_ASSOCIATED_DATA_PROCESSING_STATE_NAME);
#endif


#endif /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


    BEGIN_PLAINTEXT_PROCESSING();
    ProcessPlaintext(state, message, MESSAGE_SIZE);
    END_PLAINTEXT_PROCESSING();


#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)


#if (SKIP_STATE_CHECK_FALSE == SKIP_STATE_CHECK_PPD) && defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayVerifyData(state, STATE_SIZE, POST_PLAINTEXT_PROCESSING_STATE_NAME);
#endif
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    DisplayVerifyData(message, MESSAGE_SIZE, CIPHERTEXT_NAME);
#endif


#else /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayData(state, STATE_SIZE, POST_PLAINTEXT_PROCESSING_STATE_NAME);
#endif
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    DisplayData(message, MESSAGE_SIZE, CIPHERTEXT_NAME);
#endif


#endif /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


    /* No authentication tag in scenario 3 */
#if defined(SCENARIO) && ((SCENARIO_1 != SCENARIO) || (SCENARIO_4 != SCENARIO))


    BEGIN_ENCRYPTION_FINALIZATION();
    Finalize(state, key);
    END_ENCRYPTION_FINALIZATION();


#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)


#if (SKIP_STATE_CHECK_FALSE == SKIP_STATE_CHECK_FIN) && defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayVerifyData(state, STATE_SIZE, POST_FINALIZATION_STATE_NAME);
#endif


#else /* (SCENARIO) && ((SCENARIO_1 != SCENARIO) || (SCENARIO_4 != SCENARIO)) */


#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayData(state, STATE_SIZE, POST_FINALIZATION_STATE_NAME);
#endif


#endif /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


    BEGIN_TAG_GENERATION();
    TagGeneration(state, tag);
    END_TAG_GENERATION();


#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)


#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayVerifyData(tag, TAG_SIZE, TAG_NAME);
#endif


#else /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayData(tag, TAG_SIZE, TAG_NAME);
#endif


#endif /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


#endif /* ((SCENARIO_1 != SCENARIO) || (SCENARIO_4 != SCENARIO)) */


    /* decryption starts here */

    BEGIN_DECRYPTION_INITIALIZATION();
    Initialize(state, key, nonce);
    END_DECRYPTION_INITIALIZATION();

#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)


#if (SKIP_STATE_CHECK_FALSE == SKIP_STATE_CHECK_INI) && defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayVerifyData(state, STATE_SIZE, POST_INTIALIZATION_STATE_NAME);
#endif


#else /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayData(state, STATE_SIZE, POST_INTIALIZATION_STATE_NAME);
#endif


#endif /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


    BEGIN_DECRYPTION_ASSOCIATED_DATA_PROCESSING();
    ProcessAssociatedData(state, associatedData, ASSOCIATED_DATA_SIZE);
    END_DECRYPTION_ASSOCIATED_DATA_PROCESSING();


#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)


#if (SKIP_STATE_CHECK_FALSE == SKIP_STATE_CHECK_PAD) && defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayVerifyData(state, STATE_SIZE,
            POST_ASSOCIATED_DATA_PROCESSING_STATE_NAME);
#endif


#else /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayData(state, STATE_SIZE, POST_ASSOCIATED_DATA_PROCESSING_STATE_NAME);
#endif


#endif /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


    BEGIN_CIPHERTEXT_PROCESSING();
    ProcessCiphertext(state, message, MESSAGE_SIZE);
    END_CIPHERTEXT_PROCESSING();


#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)


#if (SKIP_STATE_CHECK_FALSE == SKIP_STATE_CHECK_PCD) && defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayVerifyData(state, STATE_SIZE, POST_CIPHERTEXT_PROCESSING_STATE_NAME);
#endif
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    DisplayVerifyData(message, MESSAGE_SIZE, PLAINTEXT_NAME);
#endif


#else /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayData(state, STATE_SIZE, POST_CIPHERTEXT_PROCESSING_STATE_NAME);
#endif
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    DisplayData(message, MESSAGE_SIZE, PLAINTEXT_NAME);
#endif


#endif /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


    /* No authentication tag in scenario 1 and 4 */
#if defined(SCENARIO) && ((SCENARIO_1 != SCENARIO) || (SCENARIO_4 != SCENARIO))


    BEGIN_DECRYPTION_FINALIZATION();
    Finalize(state, key);
    END_DECRYPTION_FINALIZATION();


#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)


#if (SKIP_STATE_CHECK_FALSE == SKIP_STATE_CHECK_FIN) && defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayVerifyData(state, STATE_SIZE, POST_FINALIZATION_STATE_NAME);
#endif


#else /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayData(state, STATE_SIZE, POST_FINALIZATION_STATE_NAME);
#endif


#endif /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


    BEGIN_TAG_VERIFICATION();
    TagVerification(state, tag);
    END_TAG_VERIFICATION();


#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)


#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayVerifyData(tag, TAG_SIZE, TAG_NAME);
    DisplayVerifyData(message, MESSAGE_SIZE, PLAINTEXT_NAME);
#endif


#else /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayData(tag, TAG_SIZE, TAG_NAME);
    DisplayData(message, MESSAGE_SIZE, PLAINTEXT_NAME);
#endif


#endif /* (SCENARIO) && (SCENARIO_0 == SCENARIO) */


#endif /* ((SCENARIO_1 != SCENARIO) || (SCENARIO_4 != SCENARIO)) */

    DONE();

    StopDevice();

    return 0;
}

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

#include <stdint.h>

#include "scenario1.h"
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

/*
 * 
 * Entry point into program
 *
 */
int main()
{
    
    RAM_DATA_BYTE message[MESSAGE_SIZE];

    RAM_DATA_BYTE state[STATE_SIZE];

    RAM_DATA_BYTE digest[DIGEST_SIZE];

    InitializeDevice();

    InitializeMessage(message, MESSAGE_SIZE);

#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayData(state, STATE_SIZE, STATE_NAME);
#endif

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    DisplayData(message, MESSAGE_SIZE, MESSAGE_NAME);
#endif

    BEGIN_INITIALIZATION();
    Initialize(state);
    END_INITIALIZATION();

#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayData(state, STATE_SIZE, POST_INTIALIZATION_STATE_NAME);
#endif

    BEGIN_UPDATE();
    UpdateScenario1(state, message);
    END_UPDATE();

#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayData(state, STATE_SIZE, POST_UPDATE_STATE_NAME);
#endif

    BEGIN_FINALIZATION();
    Finalize(state, digest);
    END_FINALIZATION();

#if defined(DEBUG) && (DEBUG_HIGH == (DEBUG_HIGH & DEBUG))
    DisplayData(state, STATE_SIZE, POST_FINALIZATION_STATE_NAME);
#endif

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    DisplayData(digest, DIGEST_SIZE, DIGEST_NAME);
#endif

    DONE();

    StopDevice();

    return 0;
}

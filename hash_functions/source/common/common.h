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

#ifndef COMMON_H
#define COMMON_H


/*
 *
 * Debug levels:
 * ... DEBUG_NO 0 - do not debug
 * ... DEBUG_LOW 1 - minimum debug level
 * ... DEBUG_MEDIUM 3 - medium debug level
 * ... DEBUG_HIGHT 7 - maximum debug level
 *
 */
#define DEBUG_NO 0
#define DEBUG_LOW 1
#define DEBUG_MEDIUM 3
#define DEBUG_HIGH 7

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG)) /* DEBUG */

extern const char *KEY_NAME;
extern const char *STATE_NAME;
extern const char *MESSAGE_NAME;
extern const char *DIGEST_NAME;
extern const char *POST_INTIALIZATION_STATE_NAME;
extern const char *POST_UPDATE_STATE_NAME;
extern const char *POST_FINALIZATION_STATE_NAME;
/*
 *
 * Display the given data arrray in hexadecimal
 * ... data - the data array to be displayed
 * ... length - the length in bytes of the data array
 * ... name - the name of the data array
 *
 */
void DisplayData(uint8_t *data, uint16_t length, const char *name);

/*
 *
 * Display and verify the given data arrray in hexadecimal
 * ... data - the data array to be displayed
 * ... length - the length in bytes of the data array
 * ... name - the name of the data array
 *
 */
void DisplayVerifyData(uint8_t *data, uint16_t length, const char *name);

/*
 *
 * Verify if the given data is the same with the expected data
 * ... data - the data array to check
 * ... name - the name of the data array
 *
 */
void VerifyData(uint8_t *data, const char *name);

#endif /* DEBUG */



#ifdef ARM /* ARM */

#if defined(MEASURE_CYCLE_COUNT) && \
    (MEASURE_CYCLE_COUNT_ENABLED == MEASURE_CYCLE_COUNT) /* MEASURE_CYCLE_COUNT */

#define BEGIN_INITIALIZATION() CYCLE_COUNT_START
#define END_INITIALIZATION() \
    CYCLE_COUNT_STOP; \
    printf("InitializationCycleCount: %u\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_UPDATE() CYCLE_COUNT_START
#define END_UPDATE() \
    CYCLE_COUNT_STOP; \
    printf("UpdateCycleCount: %u\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_FINALIZATION() CYCLE_COUNT_START
#define END_FINALIZATION() \
    CYCLE_COUNT_STOP; \
    printf("FinalizationCycleCount: %u\n", CYCLE_COUNT_ELAPSED)

#define DONE() printf("Done\n")

#else /* MEASURE_CYCLE_COUNT */

#define BEGIN_INITIALIZATION() BeginInitialization()
#define END_INITIALIZATION() EndInitialization()

#define BEGIN_UPDATE() BeginUpdate()
#define END_UPDATE() EndUpdate()

#define BEGIN_FINALIZATION() BeginFinalization()
#define END_FINALIZATION() EndFinalization()

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
#define DONE() printf("Done\n");
#else
#define DONE()
#endif

#endif /* MEASURE_CYCLE_COUNT */

#else /* ARM */

#ifdef PC /* PC */

#if defined(MEASURE_CYCLE_COUNT) && \
    (MEASURE_CYCLE_COUNT_ENABLED == MEASURE_CYCLE_COUNT) /* MEASURE_CYCLE_COUNT */

#define BEGIN_INITIALIZATION() CYCLE_COUNT_START
#define END_INITIALIZATION() \
    CYCLE_COUNT_STOP; \
    printf("InitializationCycleCount: %"PRIu64"\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_UPDATE() CYCLE_COUNT_START
#define END_UPDATE() \
    CYCLE_COUNT_STOP; \
    printf("UpdateCycleCount: %"PRIu64"\n", CYCLE_COUNT_ELAPSED)

#define BEGIN_FINALIZATION() CYCLE_COUNT_START
#define END_FINALIZATION() \
    CYCLE_COUNT_STOP; \
    printf("FinalizationCycleCount: %"PRIu64"\n", CYCLE_COUNT_ELAPSED)

#define DONE()

#else /* MEASURE_CYCLE_COUNT */

#define BEGIN_INITIALIZATION() BeginInitialization()
#define END_INITIALIZATION() EndInitialization()

#define BEGIN_UPDATE() BeginUpdate()
#define END_UPDATE() EndUpdate()

#define BEGIN_FINALIZATION() BeginFinalization()
#define END_FINALIZATION() EndFinalization()

#define DONE()

#endif /* MEASURE_CYCLE_COUNT */

#else /* PC */
/* AVR and MSP */
#define BEGIN_INITIALIZATION() BeginInitialization()
#define END_INITIALIZATION() EndInitialization()

#define BEGIN_UPDATE() BeginUpdate()
#define END_UPDATE() EndUpdate()

#define BEGIN_FINALIZATION() BeginFinalization()
#define END_FINALIZATION() EndFinalization()

#define DONE()

#endif /* PC */

#endif /* ARM */


/*
 *
 * Mark the beginning of the hash initialization
 *
 */
void BeginInitialization();

/*
 *
 * Mark the end of the hash initialization
 *
 */
void EndInitialization();

/*
 *
 * Mark the beginning of the hash Update
 *
 */
void BeginUpdate();

/*
 *
 * Mark the end of the hash Update
 *
 */
void EndUpdate();

/*
 *
 * Mark the beginning of the hash finalization
 *
 */
void BeginFinalization();

/*
 *
 * Mark the end of the hash finalization
 *
 */
void EndFinalization();

/*
 *
 * Initialize the device (architecture dependent)
 *
 */
void InitializeDevice();

/*
 *
 * Stop the device (architecture dependent)
 *
 */
void StopDevice();

/*
 *
 * Initialize the hash key
 * ... key - the key to be initialized
 *
 *
 * void InitializeKey(uint8_t *key);
 */

/*
 *
 * Initialize the message block;
 *
 * ... messageBlock - message block to be initialized
 *
 */
void InitializeMessageBlock(uint8_t *messageBlock);

/*
 *
 * Initialize the data
 * ... data - the data array to be initialized
 * ... length - the length of the data array to be initialized
 *
 */
void InitializeMessage(uint8_t *data, uint16_t length);

#endif /* COMMON_H */

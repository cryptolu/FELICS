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
#include <string.h>
#include <stdio.h>

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG)) /* DEBUG */

#include <stdio.h>

#ifdef AVR /* AVR */
#include <avr/io.h>
#include <avr/sleep.h>

#include "avr_mcu_section.h"

#ifndef F_CPU
#define F_CPU (8000000UL)
#endif

#endif /* AVR */

#endif /* DEBUG */


#ifdef MSP /* MSP */
#include <msp430.h>
#endif /* MSP */

#include "cipher.h"
#include "common.h"
#include "constants.h"
#include "test_vectors.h"

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))

const char *KEY_NAME = "Key";
const char *MESSAGE_NAME = "Message";
const char *DIGEST_NAME = "Digest";
const char *STATE_NAME = "State";
const char *POST_INTIALIZATION_STATE_NAME = "Post_Initialization_State";
const char *POST_UPDATE_STATE_NAME = "Post_Update_State";
const char *POST_FINALIZATION_STATE_NAME = "Post_Finalization_State";

void DisplayData(uint8_t *data, uint16_t length, const char *name)
{
    uint16_t i;

    printf("%s:\n", name);
    for (i = 0; i < length; i++) 
    {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void DisplayVerifyData(uint8_t *data, uint16_t length, const char *name)
{
    DisplayData(data, length, name);
#if defined(SCENARIO) && (SCENARIO_0 == SCENARIO)
    VerifyData(data, name);
#endif
}

void VerifyData(uint8_t *data, const char *name)
{
    uint8_t correct = 1;
    uint16_t length = 0;
    uint16_t i;

    const uint8_t *expectedData;

    if(0 == strcmp(name, MESSAGE_NAME))
    {
        expectedData = expectedMessage;
        length = TEST_MESSAGE_SIZE;
    }

    if(0 == strcmp(name, DIGEST_NAME))
    {
        expectedData = expectedDigest;
        length = DIGEST_SIZE;
    }

    if(0 == strcmp(name, POST_INTIALIZATION_STATE_NAME))
    {
        expectedData = expectedPostInitializationState;
        length = STATE_SIZE;
    }

    if(0 == strcmp(name, POST_UPDATE_STATE_NAME))
    {
        expectedData = expectedPostUpdateState;
        length = STATE_SIZE;
    }

    if(0 == strcmp(name, POST_FINALIZATION_STATE_NAME))
    {
        expectedData = expectedPostFinalizationState;
        length = STATE_SIZE;
    }

    if(0 == length)
    {
        return;
    }


    printf("Expected %s:\n", name);
    for(i = 0; i < length; i++)
    {
        printf("%02x ", expectedData[i]);
        if(expectedData[i] != data[i]) 
        {
            correct = 0;
        }
    }
    printf("\n");

    if(correct)
    {
        printf("CORRECT!\n");
    }
    else
    {
        printf("WRONG!\n");
    }
}

#endif


void BeginInitialization()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Initialization begin\n");
#endif
}

void EndInitialization()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Initialization end\n");
#endif
}

void BeginUpdate()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Update begin\n");
#endif
}

void EndUpdate()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Update end\n");
#endif
}

void BeginFinalization()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Finalization begin\n");
#endif
}

void EndFinalization()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    printf("->Finalization end\n");
#endif
}


#ifdef PC /* PC */

void InitializeDevice()
{

}

void StopDevice()
{

}

#endif /* PC */


#ifdef AVR /* AVR */

#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG)) /* DEBUG */

AVR_MCU(F_CPU, "atmega128");

static int uart_putchar(char c, FILE *stream)
{
    if ('\n' == c)
    {
        uart_putchar('\r', stream);
    }

    loop_until_bit_is_set(UCSR0A, UDRE0);
    UDR0 = c;

    return 0;
}

static FILE mystdout = FDEV_SETUP_STREAM(uart_putchar, NULL, _FDEV_SETUP_WRITE);
AVR_MCU_SIMAVR_CONSOLE(&UDR0);

#endif /* DEBUG */

void InitializeDevice()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    stdout = &mystdout;
#endif
}

void StopDevice()
{
#if defined(DEBUG) && (DEBUG_LOW == (DEBUG_LOW & DEBUG))
    sleep_cpu();
#endif
}

#endif /* AVR */


#ifdef MSP /* MSP */

void InitializeDevice()
{

}

void StopDevice()
{

}

#endif /* MSP */


#ifdef ARM /* ARM */

/*
 *
 * init() is defined in the sam3x8e library, so we only need a declaration here
 *
 */
extern void init(void);

void InitializeDevice()
{
    init();
}

void StopDevice()
{

}

#endif /* ARM */

void InitializeMessageBlock(uint8_t *messageBlock)
{
    uint8_t i;

    for(i = 0; i < TEST_MESSAGE_SIZE; i++)
    {
        messageBlock[i] = expectedMessage[i];
    }
}

void InitializeMessage(uint8_t *message, uint16_t length)
{
    uint16_t i;

    for(i = 0; i < length; i++)
    {
        message[i] = (uint8_t)i;
    }
}

/*
 *
 * Functions to initialize scenario-2 related data
 *


void InitializeIPOD(uint8_t *ipod, uint16_t length)
{
    uint8_t i;

    for(i = 0; i < length; i++)
    {
        ipod[i] = 0x36;
    }
}

void InitializeOPOD(uint8_t *opod, uint16_t length)
{
    uint8_t i;

    for(i = 0; i < length; i++)
    {
        opod[i] = 0x5c;
    }
}

void InitializeKEY(uint8_t *key, uint16_t length)
{
    uint8_t i;

    for(i = 0; i < length; i++)
    {
        key[i] = (uint8_t)i;
    }
}
*/
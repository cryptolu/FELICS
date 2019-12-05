/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 16-bit MSP430F1611, Fast speed code (C+ASM)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#ifndef CONSTANTS_H
#define CONSTANTS_H

#include "data_types.h"


/*
 *
 * Cipher characteristics:
 *  BLOCK_SIZE - the cipher block size in bytes
 *  KEY_SIZE - the cipher key size in bytes
 *  NONCE_SIZE - the cipher nonce size in bytes
 *  STATE_SIZE - the cipher state size
 *  TAG_SIZE - cipher tag size
 *
 */
#define BLOCK_SIZE 1 /* Replace with the cipher block size in bytes */
#define KEY_SIZE 16 /* Replace with the cipher key size in bytes */
#define NONCE_SIZE 12 /* Replace with the cipher nonce size in bytes */
#define STATE_SIZE 50 /* Replace with the cipher state size in bytes */
#define TAG_SIZE 8 /* Replace with the cipher tag size in byte */

#define TEST_ASSOCIATED_DATA_SIZE 8
#define TEST_MESSAGE_SIZE 8

#define SKIP_STATE_CHECK_INI SKIP_STATE_CHECK_TRUE
#define SKIP_STATE_CHECK_PAD SKIP_STATE_CHECK_TRUE
#define SKIP_STATE_CHECK_PPD SKIP_STATE_CHECK_TRUE
#define SKIP_STATE_CHECK_FIN SKIP_STATE_CHECK_TRUE
#define SKIP_STATE_CHECK_PCD SKIP_STATE_CHECK_TRUE

/*
 *
 * Cipher constants
 *
 */

#endif /* CONSTANTS_H */

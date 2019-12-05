/*
   Copyright : 2019 (C) Design team of Grain128-AEAD
   License   : We grant a free license to use and modify the code by anyone and in any way, for any purpose
   Cipher    : Grain128-AEAD for FELICS-AEAD framework
   Target    : 8-bit AVR ATMega 128, Fast speed code (C+ASM)
   Author    : Alexander Maximov
   Date      : 2019-11-25
 */

#include <stdint.h>

#include "test_vectors.h"

/*
 *
 * Test vectors
 *
 */

const uint8_t expectedKey[KEY_SIZE] = {
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
const uint8_t expectedNonce[NONCE_SIZE] = {
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
};
const uint8_t expectedAssociatedData[TEST_ASSOCIATED_DATA_SIZE] = {
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
};
const uint8_t expectedPlaintext[TEST_MESSAGE_SIZE] = {
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
};
const uint8_t expectedCiphertext[TEST_MESSAGE_SIZE] = {
0x72, 0x11, 0x10, 0x52, 0xd7, 0x3c, 0x41, 0x0e
};
const uint8_t expectedTag[TAG_SIZE] = {
0x8d, 0x98, 0xea, 0x68, 0xd9, 0xa2, 0xc0, 0x44
};


const uint8_t expectedPostInitializationState[STATE_SIZE] = {0};
const uint8_t expectedPostAssociatedDataProcessingState[STATE_SIZE] = {0};
const uint8_t expectedPostPlaintextProcessingState[STATE_SIZE] = {0};
const uint8_t expectedPostFinalizationState[STATE_SIZE] = {0};

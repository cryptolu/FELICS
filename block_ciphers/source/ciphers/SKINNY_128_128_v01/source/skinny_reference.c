#ifdef PC
/*
 * Date: 11 December 2015
 * Contact: Thomas Peyrin - thomas.peyrin@gmail.com
 */

/* #include <stdio.h> */
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "skinny_reference.h"
#include "cipher.h"
#include "constants.h"

/*
 * FILE* fic;
 * void display_matrix(uint8_t state[4][4], int ver)
 * {
 * int i;
 * uint8_t input[16];
 * 
 * if (versions[ver][0]==64)
 * {
 * for(i = 0; i < 8; i++) input[i] = ((state[(2*i)>>2][(2*i)&0x3] & 0xF) << 4) | (state[(2*i+1)>>2][(2*i+1)&0x3] & 0xF);
 * for(i = 0; i < 8; i++) fprintf(fic,"%02x", input[i]);
 * }
 * else if (versions[ver][0]==128)
 * {
 * for(i = 0; i < 16; i++) input[i] = state[i>>2][i&0x3] & 0xFF;
 * for(i = 0; i < 16; i++) fprintf(fic,"%02x", input[i]);
 * }
 * 
 * }
 * 
 * void display_cipher_state(uint8_t state[4][4], uint8_t keyCells[3][4][4], int ver)
 * {
 * int k;
 * 
 * fprintf(fic,"S = ");display_matrix(state,ver);
 * for(k = 0; k <(int)(versions[ver][1]/versions[ver][0]); k++)
 * {
 * fprintf(fic," - TK%i = ",k+1); display_matrix(keyCells[k],ver);
 * }
 * }
 */
/*  Extract and apply the subtweakey to the internal state (must be the two top rows XORed together), then update the tweakey state */
void AddKey(uint8_t state[4][4], uint8_t keyCells[3][4][4], int ver) {
    int i, j, k;
    uint8_t pos;
    uint8_t keyCells_tmp[3][4][4];

    /*  apply the subtweakey to the internal state */
    for (i = 0; i <= 1; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] ^= keyCells[0][i][j];
            if (2 * versions[ver][0] == versions[ver][1])
                state[i][j] ^= keyCells[1][i][j];
            else if (3 * versions[ver][0] == versions[ver][1])
                state[i][j] ^= keyCells[1][i][j] ^ keyCells[2][i][j];
        }
    }

    /*  update the subtweakey states with the permutation */
    for (k = 0; k < (int)(versions[ver][1] / versions[ver][0]); k++) {
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                /* application of the TWEAKEY permutation */
                pos = TWEAKEY_P[j + 4 * i];
                keyCells_tmp[k][i][j] = keyCells[k][pos >> 2][pos & 0x3];
            }
        }
    }

    /*  update the subtweakey states with the LFSRs */
    for (k = 0; k < (int)(versions[ver][1] / versions[ver][0]); k++) {
        for (i = 0; i <= 1; i++) {
            for (j = 0; j < 4; j++) {
                /* application of LFSRs for TK updates */
                if (k == 1) {
                    if (versions[ver][0] == 64)
                        keyCells_tmp[k][i][j] =
                                ((keyCells_tmp[k][i][j] << 1) & 0xE) ^
                                ((keyCells_tmp[k][i][j] >> 3) & 0x1) ^
                                ((keyCells_tmp[k][i][j] >> 2) & 0x1);
                    else
                        keyCells_tmp[k][i][j] =
                                ((keyCells_tmp[k][i][j] << 1) & 0xFE) ^
                                ((keyCells_tmp[k][i][j] >> 7) & 0x01) ^
                                ((keyCells_tmp[k][i][j] >> 5) & 0x01);
                } else if (k == 2) {
                    if (versions[ver][0] == 64)
                        keyCells_tmp[k][i][j] =
                                ((keyCells_tmp[k][i][j] >> 1) & 0x7) ^
                                ((keyCells_tmp[k][i][j]) & 0x8) ^
                                ((keyCells_tmp[k][i][j] << 3) & 0x8);
                    else
                        keyCells_tmp[k][i][j] =
                                ((keyCells_tmp[k][i][j] >> 1) & 0x7F) ^
                                ((keyCells_tmp[k][i][j] << 7) & 0x80) ^
                                ((keyCells_tmp[k][i][j] << 1) & 0x80);
                }
            }
        }
    }

    for (k = 0; k < (int)(versions[ver][1] / versions[ver][0]); k++) {
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                keyCells[k][i][j] = keyCells_tmp[k][i][j];
            }
        }
    }
}

void AddKeyPrecomputed(uint8_t state[4][4], uint8_t *roundKeys, int it, int ver) {
    /*
     * Modification of the original implementation of the AddKey, so it uses the
     * precomputed key schedule that was calculated using AddKey.
     */
    int i, j;

    /*  apply the subtweakey to the internal state */
    for (i = 0; i <= 1; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] ^= (roundKeys[(i * 4 + j)]);
        }
    }
}

/*  Extract and apply the subtweakey to the internal state (must be the two top rows XORed together), then update the tweakey state (inverse function} */
void AddKey_inv(uint8_t state[4][4], uint8_t keyCells[3][4][4], int ver) {
    int i, j, k;
    uint8_t pos;
    uint8_t keyCells_tmp[3][4][4];

    /*  update the subtweakey states with the permutation */
    for (k = 0; k < (int)(versions[ver][1] / versions[ver][0]); k++) {
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                /* application of the inverse TWEAKEY permutation */
                pos = TWEAKEY_P_inv[j + 4 * i];
                keyCells_tmp[k][i][j] = keyCells[k][pos >> 2][pos & 0x3];
            }
        }
    }

    /*  update the subtweakey states with the LFSRs */
    for (k = 0; k < (int)(versions[ver][1] / versions[ver][0]); k++) {
        for (i = 2; i <= 3; i++) {
            for (j = 0; j < 4; j++) {
                /* application of inverse LFSRs for TK updates */
                if (k == 1) {
                    if (versions[ver][0] == 64)
                        keyCells_tmp[k][i][j] =
                                ((keyCells_tmp[k][i][j] >> 1) & 0x7) ^
                                ((keyCells_tmp[k][i][j] << 3) & 0x8) ^
                                ((keyCells_tmp[k][i][j]) & 0x8);
                    else
                        keyCells_tmp[k][i][j] =
                                ((keyCells_tmp[k][i][j] >> 1) & 0x7F) ^
                                ((keyCells_tmp[k][i][j] << 7) & 0x80) ^
                                ((keyCells_tmp[k][i][j] << 1) & 0x80);
                } else if (k == 2) {
                    if (versions[ver][0] == 64)
                        keyCells_tmp[k][i][j] =
                                ((keyCells_tmp[k][i][j] << 1) & 0xE) ^
                                ((keyCells_tmp[k][i][j] >> 3) & 0x1) ^
                                ((keyCells_tmp[k][i][j] >> 2) & 0x1);
                    else
                        keyCells_tmp[k][i][j] =
                                ((keyCells_tmp[k][i][j] << 1) & 0xFE) ^
                                ((keyCells_tmp[k][i][j] >> 7) & 0x01) ^
                                ((keyCells_tmp[k][i][j] >> 5) & 0x01);
                }
            }
        }
    }

    for (k = 0; k < (int)(versions[ver][1] / versions[ver][0]); k++) {
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                keyCells[k][i][j] = keyCells_tmp[k][i][j];
            }
        }
    }


    /*  apply the subtweakey to the internal state */
    for (i = 0; i <= 1; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] ^= keyCells[0][i][j];
            if (2 * versions[ver][0] == versions[ver][1])
                state[i][j] ^= keyCells[1][i][j];
            else if (3 * versions[ver][0] == versions[ver][1])
                state[i][j] ^= keyCells[1][i][j] ^ keyCells[2][i][j];
        }
    }
}


/*  Apply the constants: using a LFSR counter on 6 bits, we XOR the 6 bits to the first 6 bits of the internal state */
void AddConstants(uint8_t state[4][4], int r) {
    state[0][0] ^= (RC[r] & 0xf);
    state[1][0] ^= ((RC[r] >> 4) & 0x3);
    state[2][0] ^= 0x2;
}

/*  apply the 4-bit Sbox */
void SubCell4(uint8_t state[4][4]) {
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = sbox_4[state[i][j]];
}

/*  apply the 4-bit inverse Sbox */
void SubCell4_inv(uint8_t state[4][4]) {
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = sbox_4_inv[state[i][j]];
}

/*  apply the 8-bit Sbox */
void SubCell8(uint8_t state[4][4]) {
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = sbox_8[state[i][j]];
}

/*  apply the 8-bit inverse Sbox */
void SubCell8_inv(uint8_t state[4][4]) {
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = sbox_8_inv[state[i][j]];
}

/*  Apply the ShiftRows function */
void ShiftRows(uint8_t state[4][4]) {
    int i, j, pos;

    uint8_t state_tmp[4][4];
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            /* application of the ShiftRows permutation */
            pos = P[j + 4 * i];
            state_tmp[i][j] = state[pos >> 2][pos & 0x3];
        }
    }

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] = state_tmp[i][j];
        }
    }
}

/*  Apply the inverse ShiftRows function */
void ShiftRows_inv(uint8_t state[4][4]) {
    int i, j, pos;

    uint8_t state_tmp[4][4];
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            /* application of the inverse ShiftRows permutation */
            pos = P_inv[j + 4 * i];
            state_tmp[i][j] = state[pos >> 2][pos & 0x3];
        }
    }

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[i][j] = state_tmp[i][j];
        }
    }
}

/*  Apply the linear diffusion matrix */
/* M = */
/* 1 0 1 1 */
/* 1 0 0 0 */
/* 0 1 1 0 */
/* 1 0 1 0 */
void MixColumn(uint8_t state[4][4]) {
    int j;
    uint8_t temp;

    for (j = 0; j < 4; j++) {
        state[1][j] ^= state[2][j];
        state[2][j] ^= state[0][j];
        state[3][j] ^= state[2][j];

        temp = state[3][j];
        state[3][j] = state[2][j];
        state[2][j] = state[1][j];
        state[1][j] = state[0][j];
        state[0][j] = temp;
    }
}

/*  Apply the inverse linear diffusion matrix */
void MixColumn_inv(uint8_t state[4][4]) {
    int j;
    uint8_t temp;

    for (j = 0; j < 4; j++) {
        temp = state[3][j];
        state[3][j] = state[0][j];
        state[0][j] = state[1][j];
        state[1][j] = state[2][j];
        state[2][j] = temp;

        state[3][j] ^= state[2][j];
        state[2][j] ^= state[0][j];
        state[1][j] ^= state[2][j];
    }
}
#endif

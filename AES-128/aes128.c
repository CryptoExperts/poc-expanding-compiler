/***************************************************************************
 * Implementation of Protected n-share AES-128 in C
 * 
 * This code is an implementation of a protected n-share AES-128 using 
 * compiled gadgets with the expanding circuit compiler introduced in:
 * 
 * "Random Probing Security: Verification, Composition, Expansion and New 
 * Constructions"
 * By Sonia Belaïd, Jean-Sébastien Coron, Emmanuel Prouff, Matthieu Rivain, 
 * and Abdul Rahman Taleb
 * In the proceedings of CRYPTO 2020.
 * 
 * Copyright (C) 2020 CryptoExperts
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.

***************************************************************************/

#include "aes128.h"

#include "gf256.h"


/**********************************************************
 * this file contains the full implementation of the
 * AES-128 standard procedure
**********************************************************/


uint8_t RC[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

void aes_key_schedule_128(uint8_t *key, uint8_t *roundkeys) {

    uint8_t temp[4];
    uint8_t *last4bytes; // point to the last 4 bytes of one round
    uint8_t *lastround;
    uint8_t i;

    for (i = 0; i < 16; ++i) {
        *roundkeys++ = *key++;
    }

    last4bytes = roundkeys-4;
    for (i = 0; i < AES_ROUNDS; ++i) {
        // k0-k3 for next round
        temp[3] = get_sbox_value(*last4bytes++);
        temp[0] = get_sbox_value(*last4bytes++);
        temp[1] = get_sbox_value(*last4bytes++);
        temp[2] = get_sbox_value(*last4bytes++);
        temp[0] ^= RC[i];
        lastround = roundkeys-16;
        *roundkeys++ = temp[0] ^ *lastround++;
        *roundkeys++ = temp[1] ^ *lastround++;
        *roundkeys++ = temp[2] ^ *lastround++;
        *roundkeys++ = temp[3] ^ *lastround++;
        // k4-k7 for next round        
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        // k8-k11 for next round
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        // k12-k15 for next round
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
        *roundkeys++ = *last4bytes++ ^ *lastround++;
    }
}


uint8_t exp254(uint8_t x){
	uint8_t tmp = Multiply(x, x);
	
	tmp = Multiply(tmp, tmp);
	
	tmp = Multiply(tmp, tmp);
	
	tmp = Multiply(tmp, x);
	
	tmp = Multiply(tmp, tmp);
	
	uint8_t tmp2 = Multiply(tmp, x);
	tmp = Multiply(tmp, tmp);
	
	tmp2 = Multiply(tmp2, tmp);
	tmp = Multiply(tmp, tmp);
	
	tmp = Multiply(tmp, tmp2);
	
	return Multiply(tmp, tmp);
}

uint8_t get_sbox_value(uint8_t x){
	//Exponentiation
	x = exp254(x);
	
	//Affine function
	uint8_t res = Multiply(207, x);
	res = Multiply(res, res);
	
	uint8_t tmp = Multiply(22, x);
	res = Add(res, tmp);
	res = Multiply(res, res);
	
	tmp = Multiply(1, x);
	res = Add(res, tmp);
	res = Multiply(res, res);
	
	tmp = Multiply(73, x);
	res = Add(res, tmp);
	res = Multiply(res, res);
	
	tmp = Multiply(204, x);
	res = Add(res, tmp);
	res = Multiply(res, res);
	
	tmp = Multiply(168, x);
	res = Add(res, tmp);
	res = Multiply(res, res);
	
	tmp = Multiply(238, x);
	res = Add(res, tmp);
	res = Multiply(res, res);
	
	tmp = Multiply(5, x);
	res = Add(res, tmp);
	
	res = Add(99, res);
	
	return res;	
}


uint8_t get_inv_sbox_value(uint8_t x){
	//Affine function
	uint8_t res = Multiply(147, x);
	res = Multiply(res, res);
	
	uint8_t tmp = Multiply(146, x);
	res = Add(res, tmp);
	res = Multiply(res, res);
	
	tmp = Multiply(190, x);
	res = Add(res, tmp);
	res = Multiply(res, res);
	
	tmp = Multiply(41, x);
	res = Add(res, tmp);
	res = Multiply(res, res);
	
	tmp = Multiply(73, x);
	res = Add(res, tmp);
	res = Multiply(res, res);
	
	tmp = Multiply(139, x);
	res = Add(res, tmp);
	res = Multiply(res, res);
	
	tmp = Multiply(79, x);
	res = Add(res, tmp);
	res = Multiply(res, res);
	
	tmp = Multiply(5, x);
	res = Add(res, tmp);
	
	x = Add(5, res);
	
	//Exponentiation
	return exp254(x);
	
}


void shift_rows(uint8_t *state) {
    uint8_t temp;
    // row1
    temp        = *(state+1);
    *(state+1)  = *(state+5);
    *(state+5)  = *(state+9);
    *(state+9)  = *(state+13);
    *(state+13) = temp;
    // row2
    temp        = *(state+2);
    *(state+2)  = *(state+10);
    *(state+10) = temp;
    temp        = *(state+6);
    *(state+6)  = *(state+14);
    *(state+14) = temp;
    // row3
    temp        = *(state+15);
    *(state+15) = *(state+11);
    *(state+11) = *(state+7);
    *(state+7)  = *(state+3);
    *(state+3)  = temp;
}


void inv_shift_rows(uint8_t *state) {
    uint8_t temp;
    // row1
    temp        = *(state+13);
    *(state+13) = *(state+9);
    *(state+9)  = *(state+5);
    *(state+5)  = *(state+1);
    *(state+1)  = temp;
    // row2
    temp        = *(state+14);
    *(state+14) = *(state+6);
    *(state+6)  = temp;
    temp        = *(state+10);
    *(state+10) = *(state+2);
    *(state+2)  = temp;
    // row3
    temp        = *(state+3);
    *(state+3)  = *(state+7);
    *(state+7)  = *(state+11);
    *(state+11) = *(state+15);
    *(state+15) = temp;
}


void aes_encrypt_128(uint8_t *roundkeys, uint8_t *plaintext, uint8_t *ciphertext) {

    uint8_t state[AES_BLOCK_SIZE], t;
    uint8_t i, j;

    // first AddRoundKey
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
        ciphertext[i] = Add(plaintext[i], *roundkeys++);
    }

    // 9 rounds
    for (j = 1; j < AES_ROUNDS; ++j) {

        // SubBytes
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
            state[i] = get_sbox_value(ciphertext[i]);
        }
        shift_rows(state);
        /*
         * MixColumns 
         * [02 03 01 01]   [s0  s4  s8  s12]
         * [01 02 03 01] . [s1  s5  s9  s13]
         * [01 01 02 03]   [s2  s6  s10 s14]
         * [03 01 01 02]   [s3  s7  s11 s15]
         */
        for (i = 0; i < AES_BLOCK_SIZE; i+=4)  {
            t = state[i] ^ state[i+1] ^ state[i+2] ^ state[i+3];
            
            ciphertext[i]   = Multiply(2, state[i]   ^ state[i+1]) ^ state[i]   ^ t;
            
            ciphertext[i+1] = Multiply(2, state[i+1] ^ state[i+2]) ^ state[i+1] ^ t;
            
            ciphertext[i+2] = Multiply(2, state[i+2] ^ state[i+3]) ^ state[i+2] ^ t;
            
            ciphertext[i+3] = Multiply(2, state[i+3] ^ state[i]  ) ^ state[i+3] ^ t;
        }

        // AddRoundKey
        for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
            ciphertext[i] = Add(ciphertext[i], *roundkeys++);
        }

    }
    
    // last round
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        ciphertext[i] = get_sbox_value(ciphertext[i]);
    }
    shift_rows(ciphertext);
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
        ciphertext[i] = Add(ciphertext[i], *roundkeys++);
    }

}

void aes_decrypt_128(uint8_t *roundkeys, uint8_t *ciphertext, uint8_t *plaintext) {

    uint8_t state[AES_BLOCK_SIZE];
    uint8_t t, u, v;
    uint8_t i, j;

    roundkeys += 160;

    // first round
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
        plaintext[i] = Add(ciphertext[i], roundkeys[i]);
    }
    
    roundkeys -= 16;
    inv_shift_rows(plaintext);
    
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        plaintext[i] = get_inv_sbox_value(plaintext[i]);
    }

    for (j = 1; j < AES_ROUNDS; ++j) {
        
        // Inverse AddRoundKey
        for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
            state[i] = Add(plaintext[i], roundkeys[i]);
        }
        
        /*
         * Inverse MixColumns
         * [0e 0b 0d 09]   [s0  s4  s8  s12]
         * [09 0e 0b 0d] . [s1  s5  s9  s13]
         * [0d 09 0e 0b]   [s2  s6  s10 s14]
         * [0b 0d 09 0e]   [s3  s7  s11 s15]
         */
        for (i = 0; i < AES_BLOCK_SIZE; i+=4) {
            t = state[i] ^ state[i+1] ^ state[i+2] ^ state[i+3];
            plaintext[i]   = t ^ state[i]   ^ Multiply(2, (state[i]   ^ state[i+1]));
            plaintext[i+1] = t ^ state[i+1] ^ Multiply(2, (state[i+1] ^ state[i+2]));
            plaintext[i+2] = t ^ state[i+2] ^ Multiply(2, (state[i+2] ^ state[i+3]));
            plaintext[i+3] = t ^ state[i+3] ^ Multiply(2, (state[i+3] ^ state[i]));
            u = Multiply(2, Multiply(2, (state[i]   ^ state[i+2])) );
            v = Multiply(2, Multiply(2, (state[i+1] ^ state[i+3])) );
            t = Multiply(2, (u ^ v));
            plaintext[i]   ^= t ^ u;
            plaintext[i+1] ^= t ^ v;
            plaintext[i+2] ^= t ^ u;
            plaintext[i+3] ^= t ^ v;
        }
        
        // Inverse ShiftRows
        inv_shift_rows(plaintext);
        
        // Inverse SubBytes
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
            plaintext[i] = get_inv_sbox_value(plaintext[i]);
        }

        roundkeys -= 16;

    }

    // last AddRoundKey
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
        plaintext[i] = Add(plaintext[i], roundkeys[i]);
    }

}

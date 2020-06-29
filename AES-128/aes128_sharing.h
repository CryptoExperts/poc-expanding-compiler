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

#ifndef AES128_SHARING_H
#define AES128_SHARING_H

#include <stdint.h>

/**********************************************************
 * this file contains the full implementation of the
 * AES-128 procedure in an n-share version. So basically,
 * each + (resp. *) operation is replaced by a call to 
 * add_gadget_function (resp. mult_gadget_function), and 
 * whenever a variable needs to be copied, a call to
 * copy_gadget_function is used with the necessary number
 * of calls. In addition, all variables from the standard
 * AES-128 implementation, are now replaced with n-share
 * variables of the same type (uint8_t)
**********************************************************/

void exp254_sharing(uint8_t *x, uint8_t * out);

void get_sbox_value_sharing(uint8_t * x, uint8_t * out);

void get_inv_sbox_value_sharing(uint8_t * x, uint8_t * out);


/**********************************************************
 * For shift_rows and inv_shift_rows, we are shifting 
 * complete arrays instead of single scalars (we now have
 * n-share variables). So to avoid looping over all shares
 * and copying whole arrays, we use dynamic indexing with
 * the variable ind_state and lightly tweak the code of
 * the AES encryption and decryption functions to use
 * ind_state.
**********************************************************/
void shift_rows_sharing(uint8_t ** state, uint8_t * ind_state);

void inv_shift_rows_sharing(uint8_t ** state, uint8_t * ind_state);

void mix_columns_sharing(uint8_t ** state, uint8_t ** ciphertext, uint8_t * ind_state);

void inv_mix_columns_sharing(uint8_t ** state, uint8_t ** plaintext, uint8_t * ind_state);

void aes_encrypt_128_sharing(uint8_t **roundkeys, uint8_t **plaintext, uint8_t **ciphertext);

void aes_decrypt_128_sharing(uint8_t **roundkeys, uint8_t **ciphertext, uint8_t **plaintext);

#endif

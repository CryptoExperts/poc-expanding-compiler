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

#include "aes128_sharing.h"
#include "aes128.h"

#include "gf256.h"
#include "gadgets.h"

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

void exp254_sharing(uint8_t *x, uint8_t * out){
	
	uint8_t x_copy0[NB_SHARES], x_tmp0[NB_SHARES], x_copy1[NB_SHARES], x_tmp1[NB_SHARES], x_copy2[NB_SHARES], x_copy3[NB_SHARES];
	uint8_t tmp[NB_SHARES];
	uint8_t tmp_copy0[NB_SHARES], tmp_copy1[NB_SHARES];
	uint8_t res[NB_SHARES];
	uint8_t res_copy0[NB_SHARES], res_copy1[NB_SHARES];
	uint8_t tmp2[NB_SHARES];
	uint8_t tmp_tmp0[NB_SHARES], tmp_copy2[NB_SHARES];
	uint8_t tmp2_copy0[NB_SHARES], tmp2_copy1[NB_SHARES];
	
	copy_gadget_function(x, x_copy0, x_tmp0);
	copy_gadget_function(x_tmp0, x_copy1, x_tmp1);
	copy_gadget_function(x_tmp1, x_copy2, x_copy3);
	
	mult_gadget_function(x_copy0, x_copy1, tmp);
	
	copy_gadget_function(tmp, tmp_copy0, tmp_copy1);
	mult_gadget_function(tmp_copy0, tmp_copy1, tmp);
	
	copy_gadget_function(tmp, tmp_copy0, tmp_copy1);
	mult_gadget_function(tmp_copy0, tmp_copy1, tmp);
	
	mult_gadget_function(x_copy2, tmp, res);
	
	copy_gadget_function(res, res_copy0, res_copy1);
	mult_gadget_function(res_copy0, res_copy1, tmp);
	
	
	copy_gadget_function(tmp, tmp_copy0, tmp_tmp0);
	copy_gadget_function(tmp_tmp0, tmp_copy1, tmp_copy2);
	
	mult_gadget_function(x_copy3, tmp_copy0, tmp2);
	mult_gadget_function(tmp_copy1, tmp_copy2, tmp);
	
	copy_gadget_function(tmp, tmp_copy0, tmp_tmp0);
	copy_gadget_function(tmp_tmp0, tmp_copy1, tmp_copy2);
	
	mult_gadget_function(tmp_copy0, tmp2, res);
	mult_gadget_function(tmp_copy1, tmp_copy2, tmp);
	
	mult_gadget_function(tmp, res, tmp2);
	
	copy_gadget_function(tmp2, tmp2_copy0, tmp2_copy1);
	mult_gadget_function(tmp2_copy0, tmp2_copy1, out);
}	
	

void get_sbox_value_sharing(uint8_t * x, uint8_t * out){
	
	//Exponentiation
	uint8_t new_x[NB_SHARES];
	exp254_sharing(x, new_x);	
	
	
	//Affine function
	uint8_t tmp[NB_SHARES];
	uint8_t tmp_copy0[NB_SHARES], tmp_copy1[NB_SHARES];
	uint8_t res[NB_SHARES];
	uint8_t res_copy0[NB_SHARES], res_copy1[NB_SHARES];
	uint8_t tmp2[NB_SHARES];
	uint8_t tmp2_copy0[NB_SHARES], tmp2_copy1[NB_SHARES];
	uint8_t new_x_copy0[NB_SHARES], new_x_tmp0[NB_SHARES], new_x_copy1[NB_SHARES], new_x_tmp1[NB_SHARES], new_x_copy2[NB_SHARES], new_x_tmp2[NB_SHARES], 
			new_x_copy3[NB_SHARES], new_x_tmp3[NB_SHARES], new_x_copy4[NB_SHARES], new_x_tmp4[NB_SHARES], new_x_copy5[NB_SHARES], new_x_tmp5[NB_SHARES],
			new_x_copy6[NB_SHARES], new_x_copy7[NB_SHARES];
	copy_gadget_function(new_x, new_x_copy0, new_x_tmp0); copy_gadget_function(new_x_tmp0, new_x_copy1, new_x_tmp1); copy_gadget_function(new_x_tmp1, new_x_copy2, new_x_tmp2);
	copy_gadget_function(new_x_tmp2, new_x_copy3, new_x_tmp3); copy_gadget_function(new_x_tmp3, new_x_copy4, new_x_tmp4); copy_gadget_function(new_x_tmp4, new_x_copy5, new_x_tmp5);
	copy_gadget_function(new_x_tmp5, new_x_copy6, new_x_copy7); 
	
	
	mult_cons_gadget_function(207, new_x_copy0, res);
	copy_gadget_function(res, res_copy0, res_copy1);
	mult_gadget_function(res_copy0, res_copy1, res);

	mult_cons_gadget_function(22, new_x_copy1, tmp);
	add_gadget_function(res, tmp, tmp2);
	copy_gadget_function(tmp2, tmp2_copy0, tmp2_copy1);
	mult_gadget_function(tmp2_copy0, tmp2_copy1, res);
	
	mult_cons_gadget_function(1, new_x_copy2, tmp);
	add_gadget_function(res, tmp, tmp2);
	copy_gadget_function(tmp2, tmp2_copy0, tmp2_copy1);
	mult_gadget_function(tmp2_copy0, tmp2_copy1, res);
	
	mult_cons_gadget_function(73, new_x_copy3, tmp);
	add_gadget_function(res, tmp, tmp2);
	copy_gadget_function(tmp2, tmp2_copy0, tmp2_copy1);
	mult_gadget_function(tmp2_copy0, tmp2_copy1, res);
	
	mult_cons_gadget_function(204, new_x_copy4, tmp);
	add_gadget_function(res, tmp, tmp2);
	copy_gadget_function(tmp2, tmp2_copy0, tmp2_copy1);
	mult_gadget_function(tmp2_copy0, tmp2_copy1, res);
	
	mult_cons_gadget_function(168, new_x_copy5, tmp);
	add_gadget_function(res, tmp, tmp2);
	copy_gadget_function(tmp2, tmp2_copy0, tmp2_copy1);
	mult_gadget_function(tmp2_copy0, tmp2_copy1, res);
	
	mult_cons_gadget_function(238, new_x_copy6, tmp);
	add_gadget_function(res, tmp, tmp2);
	copy_gadget_function(tmp2, tmp2_copy0, tmp2_copy1);
	mult_gadget_function(tmp2_copy0, tmp2_copy1, res);
	
	mult_cons_gadget_function(5, new_x_copy7, tmp);
	add_gadget_function(res, tmp, tmp2);
	
	add_cons_gadget_function(99, tmp2, out);

}


void get_inv_sbox_value_sharing(uint8_t * x, uint8_t * out){
	//Inverse of Affine function
	uint8_t tmp[NB_SHARES], tmp2[NB_SHARES], res[NB_SHARES];
	uint8_t tmp2_copy0[NB_SHARES], tmp2_copy1[NB_SHARES];
	uint8_t res_copy0[NB_SHARES], res_copy1[NB_SHARES];
	uint8_t x_copy0[NB_SHARES], x_tmp0[NB_SHARES], x_copy1[NB_SHARES], x_tmp1[NB_SHARES], x_copy2[NB_SHARES], x_tmp2[NB_SHARES], 
			x_copy3[NB_SHARES], x_tmp3[NB_SHARES], x_copy4[NB_SHARES], x_tmp4[NB_SHARES], x_copy5[NB_SHARES], x_tmp5[NB_SHARES],
			x_copy6[NB_SHARES], x_copy7[NB_SHARES];
	copy_gadget_function(x, x_copy0, x_tmp0); copy_gadget_function(x_tmp0, x_copy1, x_tmp1); copy_gadget_function(x_tmp1, x_copy2, x_tmp2);
	copy_gadget_function(x_tmp2, x_copy3, x_tmp3); copy_gadget_function(x_tmp3, x_copy4, x_tmp4); copy_gadget_function(x_tmp4, x_copy5, x_tmp5);
	copy_gadget_function(x_tmp5, x_copy6, x_copy7); 
	
	
	mult_cons_gadget_function(147, x_copy0, res);
	copy_gadget_function(res, res_copy0, res_copy1);
	mult_gadget_function(res_copy0, res_copy1, res);

	mult_cons_gadget_function(146, x_copy1, tmp);
	add_gadget_function(res, tmp, tmp2);
	copy_gadget_function(tmp2, tmp2_copy0, tmp2_copy1);
	mult_gadget_function(tmp2_copy0, tmp2_copy1, res);
	
	mult_cons_gadget_function(190, x_copy2, tmp);
	add_gadget_function(res, tmp, tmp2);
	copy_gadget_function(tmp2, tmp2_copy0, tmp2_copy1);
	mult_gadget_function(tmp2_copy0, tmp2_copy1, res);
	
	mult_cons_gadget_function(41, x_copy3, tmp);
	add_gadget_function(res, tmp, tmp2);
	copy_gadget_function(tmp2, tmp2_copy0, tmp2_copy1);
	mult_gadget_function(tmp2_copy0, tmp2_copy1, res);
	
	mult_cons_gadget_function(73, x_copy4, tmp);
	add_gadget_function(res, tmp, tmp2);
	copy_gadget_function(tmp2, tmp2_copy0, tmp2_copy1);
	mult_gadget_function(tmp2_copy0, tmp2_copy1, res);
	
	mult_cons_gadget_function(139, x_copy5, tmp);
	add_gadget_function(res, tmp, tmp2);
	copy_gadget_function(tmp2, tmp2_copy0, tmp2_copy1);
	mult_gadget_function(tmp2_copy0, tmp2_copy1, res);
	
	mult_cons_gadget_function(79, x_copy6, tmp);
	add_gadget_function(res, tmp, tmp2);
	copy_gadget_function(tmp2, tmp2_copy0, tmp2_copy1);
	mult_gadget_function(tmp2_copy0, tmp2_copy1, res);
	
	mult_cons_gadget_function(5, x_copy7, tmp);
	add_gadget_function(res, tmp, tmp2);
	
	uint8_t new_x[NB_SHARES];
	add_cons_gadget_function(5, tmp2, new_x);
	
	//Exponentiation
	exp254_sharing(new_x, out);
}


/**********************************************************
 * For shift_rows and inv_shift_rows, we are shifting 
 * complete arrays instead of single scalars (we now have
 * n-share variables). So to avoid looping over all shares
 * and copying whole arrays, we use dynamic indexing with
 * the variable ind_state and lightly tweak the code of
 * the AES encryption and decryption functions to use
 * ind_state.
**********************************************************/

void shift_rows_sharing(uint8_t ** state, uint8_t * ind_state){
	
	uint8_t temp;
	
	////////// row1
	temp = ind_state[1];
    
	ind_state[1] = ind_state[5];
	
	ind_state[5] = ind_state[9];
	
	ind_state[9] = ind_state[13];

	ind_state[13] = temp;

	////////// row2

	temp = ind_state[2];

	ind_state[2] = ind_state[10];

	ind_state[10] = temp;

	temp = ind_state[6];

	ind_state[6] = ind_state[14];

	ind_state[14] = temp;

	////////// row3
	temp = ind_state[15];
	
	ind_state[15] = ind_state[11];

	ind_state[11] = ind_state[7];

	ind_state[7] = ind_state[3];
	
	ind_state[3] = temp;
	
}


void inv_shift_rows_sharing(uint8_t ** state, uint8_t * ind_state){
	
	uint8_t temp;
	////////// row 1
	temp = ind_state[13];

	ind_state[13] = ind_state[9];

	ind_state[9] = ind_state[5];

	ind_state[5] = ind_state[1];

	ind_state[1] = temp;

	////////// row2
	temp = ind_state[14];

	ind_state[14] = ind_state[6];

	ind_state[6] = temp;

	temp = ind_state[10];

	ind_state[10] = ind_state[2];

	ind_state[2] = temp;

	////////// row3
	temp = ind_state[3];

	ind_state[3] = ind_state[7];

	ind_state[7] = ind_state[11];

	ind_state[11] = ind_state[15];

	ind_state[15] = temp;
}


void mix_columns_sharing(uint8_t ** state, uint8_t ** ciphertext, uint8_t * ind_state){
	uint8_t t[NB_SHARES];
	uint8_t tmp[NB_SHARES];
	/*
	 * MixColumns 
	 * [02 03 01 01]   [s0  s4  s8  s12]
	 * [01 02 03 01] . [s1  s5  s9  s13]
	 * [01 01 02 03]   [s2  s6  s10 s14]
	 * [03 01 01 02]   [s3  s7  s11 s15]
	 */
	for (int i = 0; i < AES_BLOCK_SIZE; i+=4)  {
		uint8_t statei_copy0[NB_SHARES], statei_tmp0[NB_SHARES], statei_copy1[NB_SHARES], statei_tmp1[NB_SHARES],
				statei_copy2[NB_SHARES], statei_copy3[NB_SHARES];
		copy_gadget_function(state[ind_state[i]], statei_copy0, statei_tmp0); copy_gadget_function(statei_tmp0, statei_copy1, statei_tmp1);
		copy_gadget_function(statei_tmp1, statei_copy2, statei_copy3);
		
		uint8_t statei1_copy0[NB_SHARES], statei1_tmp0[NB_SHARES], statei1_copy1[NB_SHARES], statei1_tmp1[NB_SHARES],
				statei1_copy2[NB_SHARES], statei1_copy3[NB_SHARES];
		copy_gadget_function(state[ind_state[i+1]], statei1_copy0, statei1_tmp0); copy_gadget_function(statei1_tmp0, statei1_copy1, statei1_tmp1);
		copy_gadget_function(statei1_tmp1, statei1_copy2, statei1_copy3);
		
		uint8_t statei2_copy0[NB_SHARES], statei2_tmp0[NB_SHARES], statei2_copy1[NB_SHARES], statei2_tmp1[NB_SHARES],
				statei2_copy2[NB_SHARES], statei2_copy3[NB_SHARES];
		copy_gadget_function(state[ind_state[i+2]], statei2_copy0, statei2_tmp0); copy_gadget_function(statei2_tmp0, statei2_copy1, statei2_tmp1);
		copy_gadget_function(statei2_tmp1, statei2_copy2, statei2_copy3);
		
		uint8_t statei3_copy0[NB_SHARES], statei3_tmp0[NB_SHARES], statei3_copy1[NB_SHARES], statei3_tmp1[NB_SHARES],
				statei3_copy2[NB_SHARES], statei3_copy3[NB_SHARES];
		copy_gadget_function(state[ind_state[i+3]], statei3_copy0, statei3_tmp0); copy_gadget_function(statei3_tmp0, statei3_copy1, statei3_tmp1);
		copy_gadget_function(statei3_tmp1, statei3_copy2, statei3_copy3);


		//t = state[i] ^ state[i+1] ^ state[i+2] ^ state[i+3];
		add_gadget_function(statei_copy0, statei1_copy0, t);
		add_gadget_function(statei2_copy0, t, tmp);
		add_gadget_function(statei3_copy0, tmp, t);
		
		uint8_t t_copy0[NB_SHARES], t_tmp0[NB_SHARES], t_copy1[NB_SHARES], t_tmp1[NB_SHARES], t_copy2[NB_SHARES], t_copy3[NB_SHARES];
		copy_gadget_function(t, t_copy0, t_tmp0); copy_gadget_function(t_tmp0, t_copy1, t_tmp1); copy_gadget_function(t_tmp1, t_copy2, t_copy3);
		
		
		//ciphertext[i]   = Multiply(2, state[i]   ^ state[i+1]) ^ state[i]   ^ t;
		add_gadget_function(statei_copy1, statei1_copy1, tmp);
		mult_cons_gadget_function(2, tmp, t);
		add_gadget_function(statei_copy2, t, tmp);
		add_gadget_function(tmp, t_copy0, ciphertext[ind_state[i]]);
		
		//ciphertext[i+1] = Multiply(2, state[i+1] ^ state[i+2]) ^ state[i+1] ^ t;
		add_gadget_function(statei1_copy2, statei2_copy1, tmp);
		mult_cons_gadget_function(2, tmp, t);
		add_gadget_function(statei1_copy3, t, tmp);
		add_gadget_function(tmp, t_copy1, ciphertext[ind_state[i+1]]);
		
		
		//ciphertext[i+2] = Multiply(2, state[i+2] ^ state[i+3]) ^ state[i+2] ^ t;
		add_gadget_function(statei2_copy2, statei3_copy1, tmp);
		mult_cons_gadget_function(2, tmp, t);
		add_gadget_function(statei2_copy3, t, tmp);
		add_gadget_function(tmp, t_copy2, ciphertext[ind_state[i+2]]);
		
		
		//ciphertext[i+3] = Multiply(2, state[i+3] ^ state[i]  ) ^ state[i+3] ^ t;
		add_gadget_function(statei3_copy2, statei_copy3, tmp);
		mult_cons_gadget_function(2, tmp, t);
		add_gadget_function(statei3_copy3, t, tmp);
		add_gadget_function(tmp, t_copy3, ciphertext[ind_state[i+3]]);
	}
}


void inv_mix_columns_sharing(uint8_t ** state, uint8_t ** plaintext, uint8_t * ind_state){
	uint8_t t[NB_SHARES], u[NB_SHARES], v[NB_SHARES];
	uint8_t tmp[NB_SHARES];
	/*
	* Inverse MixColumns
	* [0e 0b 0d 09]   [s0  s4  s8  s12]
	* [09 0e 0b 0d] . [s1  s5  s9  s13]
	* [0d 09 0e 0b]   [s2  s6  s10 s14]
	* [0b 0d 09 0e]   [s3  s7  s11 s15]
	*/
	for (uint8_t i = 0; i < AES_BLOCK_SIZE; i+=4) {
		uint8_t statei_copy0[NB_SHARES], statei_tmp0[NB_SHARES], statei_copy1[NB_SHARES], statei_tmp1[NB_SHARES],
				statei_copy2[NB_SHARES], statei_tmp2[NB_SHARES], statei_copy3[NB_SHARES], statei_copy4[NB_SHARES];
		copy_gadget_function(state[ind_state[i]], statei_copy0, statei_tmp0); copy_gadget_function(statei_tmp0, statei_copy1, statei_tmp1);
		copy_gadget_function(statei_tmp1, statei_copy2, statei_tmp2); copy_gadget_function(statei_tmp2, statei_copy3, statei_copy4);
		
		uint8_t statei1_copy0[NB_SHARES], statei1_tmp0[NB_SHARES], statei1_copy1[NB_SHARES], statei1_tmp1[NB_SHARES],
				statei1_copy2[NB_SHARES], statei1_tmp2[NB_SHARES], statei1_copy3[NB_SHARES], statei1_copy4[NB_SHARES];
		copy_gadget_function(state[ind_state[i+1]], statei1_copy0, statei1_tmp0); copy_gadget_function(statei1_tmp0, statei1_copy1, statei1_tmp1);
		copy_gadget_function(statei1_tmp1, statei1_copy2, statei1_tmp2); copy_gadget_function(statei1_tmp2, statei1_copy3, statei1_copy4);
		
		uint8_t statei2_copy0[NB_SHARES], statei2_tmp0[NB_SHARES], statei2_copy1[NB_SHARES], statei2_tmp1[NB_SHARES],
				statei2_copy2[NB_SHARES], statei2_tmp2[NB_SHARES], statei2_copy3[NB_SHARES], statei2_copy4[NB_SHARES];
		copy_gadget_function(state[ind_state[i+2]], statei2_copy0, statei2_tmp0); copy_gadget_function(statei2_tmp0, statei2_copy1, statei2_tmp1);
		copy_gadget_function(statei2_tmp1, statei2_copy2, statei2_tmp2); copy_gadget_function(statei2_tmp2, statei2_copy3, statei2_copy4);
		
		uint8_t statei3_copy0[NB_SHARES], statei3_tmp0[NB_SHARES], statei3_copy1[NB_SHARES], statei3_tmp1[NB_SHARES],
				statei3_copy2[NB_SHARES], statei3_tmp2[NB_SHARES], statei3_copy3[NB_SHARES], statei3_copy4[NB_SHARES];
		copy_gadget_function(state[ind_state[i+3]], statei3_copy0, statei3_tmp0); copy_gadget_function(statei3_tmp0, statei3_copy1, statei3_tmp1);
		copy_gadget_function(statei3_tmp1, statei3_copy2, statei3_tmp2); copy_gadget_function(statei3_tmp2, statei3_copy3, statei3_copy4);
		
		
		//t = state[i] ^ state[i+1] ^ state[i+2] ^ state[i+3];
		add_gadget_function(statei_copy0, statei1_copy0, t);
		add_gadget_function(statei2_copy0, t, tmp);
		add_gadget_function(statei3_copy0, tmp, t);
		
		uint8_t t_copy0[NB_SHARES], t_tmp0[NB_SHARES], t_copy1[NB_SHARES], t_tmp1[NB_SHARES], t_copy2[NB_SHARES], t_copy3[NB_SHARES];
		copy_gadget_function(t, t_copy0, t_tmp0); copy_gadget_function(t_tmp0, t_copy1, t_tmp1); copy_gadget_function(t_tmp1, t_copy2, t_copy3);
		
		//plaintext[i]   = t ^ state[i]   ^ mul2(state[i]   ^ state[i+1]);
		add_gadget_function(statei_copy1, statei1_copy1, tmp);
		mult_cons_gadget_function(2, tmp, t);
		add_gadget_function(statei_copy2, t, tmp);
		add_gadget_function(tmp, t_copy0, plaintext[ind_state[i]]);
		
		//plaintext[i+1] = t ^ state[i+1] ^ mul2(state[i+1] ^ state[i+2]);
		add_gadget_function(statei1_copy2, statei2_copy1, tmp);
		mult_cons_gadget_function(2, tmp, t);
		add_gadget_function(statei1_copy3, t, tmp);
		add_gadget_function(tmp, t_copy1, plaintext[ind_state[i+1]]);
		
		
		//plaintext[i+2] = t ^ state[i+2] ^ mul2(state[i+2] ^ state[i+3]);
		add_gadget_function(statei2_copy2, statei3_copy1, tmp);
		mult_cons_gadget_function(2, tmp, t);
		add_gadget_function(statei2_copy3, t, tmp);
		add_gadget_function(tmp, t_copy2, plaintext[ind_state[i+2]]);
		
		
		//plaintext[i+3] = t ^ state[i+3] ^ mul2(state[i+3] ^ state[i]);
		add_gadget_function(statei3_copy2, statei_copy3, tmp);
		mult_cons_gadget_function(2, tmp, t);
		add_gadget_function(statei3_copy3, t, tmp);
		add_gadget_function(tmp, t_copy3, plaintext[ind_state[i+3]]);
		
		
		//u = Multiply(2, Multiply(2, (state[i]   ^ state[i+2])) );
		add_gadget_function(statei_copy4, statei2_copy4, tmp);
		mult_cons_gadget_function(2, tmp, t);
		mult_cons_gadget_function(2, t, u);
		
		//v = Multiply(2, Multiply(2, (state[i+1] ^ state[i+3])) );
		add_gadget_function(statei1_copy4, statei3_copy4, tmp);
		mult_cons_gadget_function(2, tmp, t);
		mult_cons_gadget_function(2, t, v);
		
		uint8_t u_copy0[NB_SHARES], u_tmp0[NB_SHARES], u_copy1[NB_SHARES], u_copy2[NB_SHARES];
		copy_gadget_function(u, u_copy0, u_tmp0); copy_gadget_function(u_tmp0, u_copy1, u_copy2);
		
		uint8_t v_copy0[NB_SHARES], v_tmp0[NB_SHARES], v_copy1[NB_SHARES], v_copy2[NB_SHARES];
		copy_gadget_function(v, v_copy0, v_tmp0); copy_gadget_function(v_tmp0, v_copy1, v_copy2);
		
		//t = Multiply(2, (u ^ v));    
		add_gadget_function(u_copy0, v_copy0, tmp);
		mult_cons_gadget_function(2, tmp, t);
		
		copy_gadget_function(t, t_copy0, t_tmp0); copy_gadget_function(t_tmp0, t_copy1, t_tmp1); copy_gadget_function(t_tmp1, t_copy2, t_copy3);
		
		//plaintext[i]   ^= t ^ u;
		add_gadget_function(plaintext[ind_state[i]], t_copy0, tmp);
		add_gadget_function(u_copy1, tmp, plaintext[ind_state[i]]);
		
		//plaintext[i+1] ^= t ^ v;
		add_gadget_function(plaintext[ind_state[i+1]], t_copy1, tmp);
		add_gadget_function(v_copy1, tmp, plaintext[ind_state[i+1]]);
		
		//plaintext[i+2] ^= t ^ u;
		add_gadget_function(plaintext[ind_state[i+2]], t_copy2, tmp);
		add_gadget_function(u_copy2, tmp, plaintext[ind_state[i+2]]);
		
		//plaintext[i+3] ^= t ^ v;
		add_gadget_function(plaintext[ind_state[i+3]], t_copy3, tmp);
		add_gadget_function(v_copy2, tmp, plaintext[ind_state[i+3]]);
	}
        

}


void aes_encrypt_128_sharing(uint8_t **roundkeys, uint8_t **plaintext, uint8_t **ciphertext){
	
	uint8_t ** state = (uint8_t **)malloc(AES_BLOCK_SIZE * sizeof(uint8_t *));
	uint8_t ind_state[AES_BLOCK_SIZE];
	for(int i=0; i< AES_BLOCK_SIZE; i++){
		state[i] = (uint8_t *)malloc(NB_SHARES * sizeof(uint8_t));
		ind_state[i] = i;
	}	
	uint8_t tmp[NB_SHARES];
    uint8_t i, j;

	int ind_roundkeys = 0;
	int ind;

    // first AddRoundKey
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
		add_gadget_function(plaintext[i], roundkeys[ind_roundkeys], ciphertext[i]);
        ind_roundkeys++;
    }

    // 9 rounds
    for (j = 1; j < AES_ROUNDS; ++j) {

        // SubBytes
        for (i = 0; i < AES_BLOCK_SIZE; ++i) {
			get_sbox_value_sharing(ciphertext[ind_state[i]], state[ind_state[i]]);
        }
        
        shift_rows_sharing(state, ind_state);
        /*
         * MixColumns 
         * [02 03 01 01]   [s0  s4  s8  s12]
         * [01 02 03 01] . [s1  s5  s9  s13]
         * [01 01 02 03]   [s2  s6  s10 s14]
         * [03 01 01 02]   [s3  s7  s11 s15]
         */
         mix_columns_sharing(state, ciphertext, ind_state);

        // AddRoundKey
        for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
			
			add_gadget_function(ciphertext[ind_state[i]], roundkeys[ind_roundkeys], tmp);
			ind_roundkeys++;
            for(ind=0; ind<NB_SHARES; ind++){
				ciphertext[ind_state[i]][ind] = tmp[ind];
			}
        }
    }

    // last round
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        get_sbox_value_sharing(ciphertext[ind_state[i]], tmp);
        for(ind=0; ind<NB_SHARES; ind++){
			ciphertext[ind_state[i]][ind] = tmp[ind];
		}
    }
    
    shift_rows_sharing(ciphertext, ind_state);
    
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
		add_gadget_function(ciphertext[ind_state[i]], roundkeys[ind_roundkeys], state[ind_state[i]]);
		ind_roundkeys++;
    }
    
    for(i=0; i< AES_BLOCK_SIZE; i++){
		/*for(ind =0; ind< NB_SHARES; ind++){
			ciphertext[i][ind] = state[ind_state[i]][ind];
		}*/
		memcpy(ciphertext[i], state[ind_state[i]], NB_SHARES*sizeof(uint8_t));
	}
    
    for(i=0; i< AES_BLOCK_SIZE; i++){
		free(state[i]);
	}	
	free(state);
}




void aes_decrypt_128_sharing(uint8_t **roundkeys, uint8_t **ciphertext, uint8_t **plaintext){
	
	
	uint8_t ** state = (uint8_t **)malloc(AES_BLOCK_SIZE * sizeof(uint8_t *));
	uint8_t ind_state[AES_BLOCK_SIZE];
	for(int i=0; i< AES_BLOCK_SIZE; i++){
		state[i] = (uint8_t *)malloc(NB_SHARES * sizeof(uint8_t));
		ind_state[i] = i;
	}	
	uint8_t tmp[NB_SHARES];
    uint8_t i, j;

	int ind_roundkeys = 160;
	int ind;

    // first Round
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
		add_gadget_function(ciphertext[ind_state[i]], roundkeys[ind_roundkeys], plaintext[ind_state[i]]);
        ind_roundkeys++;
    }
    ind_roundkeys -= 32;
    inv_shift_rows_sharing(plaintext, ind_state);
    
    // Inverse SubBytes
	for (i = 0; i < AES_BLOCK_SIZE; ++i) {
		get_inv_sbox_value_sharing(plaintext[ind_state[i]], plaintext[ind_state[i]]);
	}

    // 9 rounds
    for (j = 1; j < AES_ROUNDS; ++j) {
		
		// Inverse AddRoundKey
        for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
			add_gadget_function(plaintext[ind_state[i]], roundkeys[ind_roundkeys], state[ind_state[i]]);
			ind_roundkeys++;
        }
        ind_roundkeys -= 32;
        
        /*
         * Inverse MixColumns
         * [0e 0b 0d 09]   [s0  s4  s8  s12]
         * [09 0e 0b 0d] . [s1  s5  s9  s13]
         * [0d 09 0e 0b]   [s2  s6  s10 s14]
         * [0b 0d 09 0e]   [s3  s7  s11 s15]
         */
         inv_mix_columns_sharing(state, plaintext, ind_state);
         
         // Inverse ShiftRows
         inv_shift_rows_sharing(plaintext, ind_state);
         
         
		// Inverse SubBytes
		for (i = 0; i < AES_BLOCK_SIZE; ++i) {
			get_inv_sbox_value_sharing(plaintext[ind_state[i]], plaintext[ind_state[i]]);
		}
		
    }
    
    // last AddRoundKey
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
		add_gadget_function(plaintext[ind_state[i]], roundkeys[ind_roundkeys], state[ind_state[i]]);
		ind_roundkeys++;
    }
    
    
    for(i=0; i< AES_BLOCK_SIZE; i++){
		/*for(ind =0; ind< NB_SHARES; ind++){
			ciphertext[i][ind] = state[ind_state[i]][ind];
		}*/
		memcpy(plaintext[i], state[ind_state[i]], NB_SHARES*sizeof(uint8_t));
	}
    
    for(i=0; i< AES_BLOCK_SIZE; i++){
		free(state[i]);
	}	
	free(state);
	
}

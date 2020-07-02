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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include "./aes_files/gf256.h"
#include "./aes_files/aes128.h"
#include "./aes_files/gadgets.h"
#include "./aes_files/aes128_sharing.h"

double my_gettimeofday(){
  struct timeval tmp_time;
  gettimeofday(&tmp_time, NULL);
  return tmp_time.tv_sec + (tmp_time.tv_usec * 1.0e-6L);
}

int main(int argc, char ** argv){
	
	for(int i=0; i<NB_SHARES; i++){
		const_s[i] = 0;
	}
	
	srand(time(NULL));
	
	double start, end, aes_enc, aes_dec, aes_sharing_enc, aes_sharing_dec;
	
	/*uint8_t a[NB_SHARES], b[NB_SHARES], c[NB_SHARES];
	for(int i=0; i< NB_SHARES; i++){
		a[i] = rand()%256;
		b[i] = rand()%256;
	}
	
	double total = 0;
	double nb_times = 1;
	
	for(int i=0; i<nb_times; i++){
		start = my_gettimeofday();
		add_gadget_function(a, b, c);
		end = my_gettimeofday();
		total += ((end-start) * 1000);
	}
	printf("Add Time for %d shares = %lf ms\n", NB_SHARES, total/nb_times);
	
	total = 0;
	for(int i=0; i<nb_times; i++){
		start = my_gettimeofday();
		copy_gadget_function(a, b, c);
		end = my_gettimeofday();
		total += ((end-start) * 1000);
	}
	printf("Copy Time for %d shares = %lf ms\n", NB_SHARES, total/nb_times);
	
	total = 0;
	for(int i=0; i<nb_times; i++){
		start = my_gettimeofday();
		mult_gadget_function(a, b, c);
		end = my_gettimeofday();
		total += ((end-start) * 1000);
	}
	printf("Mult Time for %d shares = %lf ms\n", NB_SHARES, total/nb_times);
	
	return 0;*/
	uint8_t i, r;
	/* 128 bit key */
	uint8_t key[] = {
		0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59, 
		0x0c, 0xb7, 0xad, 0xd6, 0xaf, 0x7f, 0x67, 0x98,
		//0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		//0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 

	};

	uint8_t plaintext[] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		//0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		//0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	};
	
	const uint8_t const_cipher[AES_BLOCK_SIZE] = {
		0xff, 0x0b, 0x84, 0x4a, 0x08, 0x53, 0xbf, 0x7c,
		0x69, 0x34, 0xab, 0x43, 0x64, 0x14, 0x8f, 0xb9,
		//0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
		//0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
	};
	
	uint8_t ciphertext[AES_BLOCK_SIZE];
	uint8_t roundkeys[AES_ROUND_KEY_SIZE];
	
	aes_key_schedule_128(key, roundkeys);
	printf("Round Keys:\n");
	for ( r = 0; r <= AES_ROUNDS; r++ ) {
		for (i = 0; i < AES_BLOCK_SIZE; i++) {
			printf("%2x ", roundkeys[r*AES_BLOCK_SIZE+i]);
		}
		printf("\n");
	}
	printf("\n");
	
	uint8_t plaintext_res[AES_BLOCK_SIZE];
	
	/*************************** AES-128 Standard Encryption / Decryption ***************************/
	start = my_gettimeofday();
	aes_encrypt_128(roundkeys, plaintext, ciphertext);
	end = my_gettimeofday();
	aes_enc = end - start;
	
	start = my_gettimeofday();
	aes_decrypt_128(roundkeys, ciphertext, plaintext_res);
	end = my_gettimeofday();
	aes_dec = end - start;
	
	/*************************** Verifying that AES decryption gives back original plaintext ***************************/
	for(i=0; i<AES_BLOCK_SIZE; i++){
		if(plaintext[i] != plaintext_res[i]){
			printf("DECRYPT ERROR\n");
			exit(EXIT_FAILURE);
		}
	}
	printf("REGULAR ENCRYPTION SUCCESS\n");
	
	
	/*************************** Generating Sharings of texts and keys ***************************/
	uint8_t ** plaintext_sharing = (uint8_t **)malloc(AES_BLOCK_SIZE * sizeof(uint8_t *));
	uint8_t ** plaintext_res_sharing = (uint8_t **)malloc(AES_BLOCK_SIZE * sizeof(uint8_t *));
	uint8_t ** ciphertext_sharing = (uint8_t **)malloc(AES_BLOCK_SIZE * sizeof(uint8_t *));
	for(i =0; i< AES_BLOCK_SIZE; i++){
		plaintext_sharing[i] = (uint8_t *)malloc(NB_SHARES * sizeof(uint8_t));
		plaintext_res_sharing[i] = (uint8_t *)malloc(NB_SHARES * sizeof(uint8_t));
		ciphertext_sharing[i] = (uint8_t *)malloc(NB_SHARES * sizeof(uint8_t));
	}
	uint8_t ** roundkeys_sharing = (uint8_t **)malloc(AES_ROUND_KEY_SIZE * sizeof(uint8_t *));
	for(i=0; i<AES_ROUND_KEY_SIZE; i++){
		roundkeys_sharing[i] = (uint8_t *)malloc(NB_SHARES * sizeof(uint8_t));
	}
	
	for(i =0; i<AES_BLOCK_SIZE; i++){
		generate_n_sharing(plaintext[i], plaintext_sharing[i]);
		generate_n_sharing(0, ciphertext_sharing[i]);
	}
	for(i =0; i<AES_ROUND_KEY_SIZE; i++){
		generate_n_sharing(roundkeys[i], roundkeys_sharing[i]);
	}
	
	
	/*************************** AES-128 Sharing Secure Encryption / Decryption ***************************/
	start = my_gettimeofday();
	aes_encrypt_128_sharing(roundkeys_sharing, plaintext_sharing, ciphertext_sharing);
	end = my_gettimeofday();
	aes_sharing_enc = end - start;
	
	start = my_gettimeofday();
	aes_decrypt_128_sharing(roundkeys_sharing, ciphertext_sharing, plaintext_res_sharing);
	end = my_gettimeofday();
	aes_sharing_dec = end - start;
	
	
	/*************************** Verifying that both standard and sharing encryption give the same ciphertext output ***************************/
	for(i=0; i< AES_BLOCK_SIZE; i++){
		if(ciphertext[i] != compress_n_sharing(ciphertext_sharing[i])){
			printf("\nENCRYPT WRONG\n\n");
			exit(EXIT_FAILURE);
		}
	}
	
	
	/*************************** Verifying that sharing AES decryption gives back the original plaintext ***************************/
	for(i=0; i<AES_BLOCK_SIZE; i++){
		if(compress_n_sharing(plaintext_sharing[i]) != compress_n_sharing(plaintext_res_sharing[i])){
			printf("DECRYPT ERROR\n");
			exit(EXIT_FAILURE);
		}
	}
	printf("SHARING ENCRYPTION SUCCESS\n");
	
	/*for(i=0; i<AES_BLOCK_SIZE; i++){
		ciphertext[i] = compress_n_sharing(ciphertext_sharing[i]);
	}*/


	/*************************** Printing Ciphertext ***************************/
	printf("\nCipher text:\n");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		printf("%2x ", compress_n_sharing(ciphertext_sharing[i]));
	}
	printf("\n");
	
	/*for (i = 0; i < AES_BLOCK_SIZE; i++) {
		if ( ciphertext[i] != const_cipher[i] ) { break; }
	}
	if ( AES_BLOCK_SIZE != i ) { printf("\nENCRYPT WRONG\n\n"); }
	else { printf("\nENCRYPT CORRECT\n\n"); }*/
	
	
	printf("\n\nTimings: \n");
	printf("\nAES standard enc took %lf ms\n", aes_enc * 1000);
	printf("\nAES standard dec took %lf ms\n", aes_dec * 1000);
	
	printf("\n\nAES sharing enc took %lf ms\n", aes_sharing_enc * 1000);
	printf("\nAES sharing dec took %lf ms\n", aes_sharing_dec * 1000);

	for(i =0; i< AES_BLOCK_SIZE; i++){
		free(plaintext_sharing[i]);
		free(ciphertext_sharing[i]);
	}
	for(i=0; i<AES_ROUND_KEY_SIZE; i++){
		free(roundkeys_sharing[i]);
	}
	free(plaintext_sharing);
	free(ciphertext_sharing);
	free(roundkeys_sharing);
	
	return 0;
	
	
}

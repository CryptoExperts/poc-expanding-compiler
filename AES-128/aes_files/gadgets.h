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

#ifndef GADGETS_H
#define GADGETS_H

#include <stdint.h>

#define NB_SHARES 27

static uint8_t const_s[NB_SHARES];

/**********************************************************
 * For the generation of random values,we  assume  
 * the  availability  of  an  efficient  (pseudo)random  
 * number  generator,  and  so  we  simply consider
 *  the values of an incremented counter variable to 
 * simulate the cost
**********************************************************/
static uint8_t counter = 0;
#ifndef get_rand()
#define get_rand() counter++ ^ 0xff
#endif

/**********************************************************
 * Creates a n-share randomized variable of
 *  the variable a, and stores it in the array a_sharing
**********************************************************/
void generate_n_sharing(uint8_t a, uint8_t * a_sharing);


/**********************************************************
 * Returns the value of the variable stored in the 
 * randomized n-share variable a_sharing (simply xors
 * all the shares)
**********************************************************/
uint8_t compress_n_sharing(uint8_t * a_sharing);


/**********************************************************
 * cons : constant value
 * a : n-share input variable
 * c : n-share output variable
 * Computes c = a + cons by creating a sharing of cons
 * as (cons, 0, ..., 0) and calling the addition gadget
**********************************************************/
void add_cons_gadget_function(uint8_t cons, uint8_t * a, uint8_t * c);


/**********************************************************
 * cons : constant value
 * a : n-share input variable
 * c : n-share output variable
 * Computes c = a * cons by creating a sharing of cons
 * as (cons, 0, ..., 0) and calling the 
 * multiplicaction gadget
**********************************************************/
void mult_cons_gadget_function(uint8_t cons, uint8_t * a, uint8_t * c);


/**********************************************************
 * a : n-share input variable
 * b : n-share input variable
 * c : n-share output variable
 * n-share addition gadget that computes c = a + b
**********************************************************/
void add_gadget_function(uint8_t * a, uint8_t * b, uint8_t * c);


/**********************************************************
 * a : n-share input variable
 * d : n-share output variable
 * e : n-share output variable
 * n-share copy gadgets that creates d and e, fresh copies 
 * of a
**********************************************************/
void copy_gadget_function(uint8_t * a, uint8_t * d, uint8_t * e);


/**********************************************************
 * a : n-share input variable
 * b : n-share input variable
 * c : n-share output variable
 * n-share multiplication gadget that computes c = a * b
**********************************************************/
void mult_gadget_function(uint8_t * a, uint8_t * b, uint8_t * c);




#endif

/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
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

#include "cipher.h"
#include "constants.h"
#include "primitives.h"


void Decrypt(uint8_t *block, uint8_t *roundKeys) {
	register uint8_t i;
	register uint32_t w0, w1, w2, w3;
	register uint32_t k0, k1, k2, k3;
	register uint32_t temp0, temp1;
	register uint8_t RC;

  	w0 = ((uint32_t*) block)[0];
	w1 = ((uint32_t*) block)[1];
	w2 = ((uint32_t*) block)[2];
	w3 = ((uint32_t*) block)[3];

	k0 = ((uint32_t*) roundKeys)[0];
	k1 = ((uint32_t*) roundKeys)[1];
	k2 = ((uint32_t*) roundKeys)[2];
	k3 = ((uint32_t*) roundKeys)[3];
  
	RC = RC2DECRYPTSTART;

  	/* ------ THETA(k, NullVector) -------- */
	THETA(k0, k1, k2, k3, 0, 0, 0, 0, temp0, temp1)
	/* --------------------- */

	for(i = NUMBER_OF_ROUNDS; i > 0; i--) {
		/* ------ THETA(w, k) -------- */
		THETA(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1)
		/* --------------------- */

		w0 ^= RC;
		
		/* ------ PI1 -------- */
		PI1(w0, w1, w2, w3)
		/* ------------------- */

		/* ------ GAMMA -------- */
		GAMMA(w0, w1, w2, w3, temp0)
		/* --------------------- */

		/* ------ PI2 -------- */
		PI2(w0, w1, w2, w3)
		/* ------------------- */

		RCSHIFTREGBWD(RC)
	}

	/* ------ THETA(w, k) -------- */
	THETA(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1)
	/* --------------------- */

 	w0 ^= RC;

	((uint32_t*) block)[0] = w0;
	((uint32_t*) block)[1] = w1;
	((uint32_t*) block)[2] = w2;
	((uint32_t*) block)[3] = w3;
}

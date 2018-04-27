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

#include "constants.h"
#include "primitives.h"

/*
 *
 * Cipher primitives
 *
 */

/*==================================================================================*/
void CommonLoop (uint32_t* const block, const uint32_t* const key, const uint8_t* const RC1, const uint8_t* const RC2)
{ 
  register uint32_t w0, w1, w2, w3;
	register uint32_t k0, k1, k2, k3;
	register uint32_t temp0, temp1;
  register int32_t i, j;

	w0 = block[0];
	w1 = block[1];
	w2 = block[2];
	w3 = block[3];

	k0 = key[0];
	k1 = key[1];
	k2 = key[2];
	k3 = key[3];

  j = 0;

  for(i = NUMBER_OF_ROUNDS; i > 0; i--) {
    w0 ^= RC1[j];
      
    /* ------ THETA(w, k) -------- */
    THETA(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1)
    /* --------------------- */
    
    w0 ^= RC2[i];
    
    /* ------ PI1 -------- */
    PI1(w0, w1, w2, w3)
    /* ------------------- */

    /* ------ GAMMA -------- */
    GAMMA(w0, w1, w2, w3, temp0)
    /* --------------------- */

    /* ------ PI2 -------- */
    PI2(w0, w1, w2, w3)
    /* ------------------- */

    j++;
  }

  w0 ^= RC1[NUMBER_OF_ROUNDS];
	
	/* ------ THETA(w, k) -------- */
	THETA(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1)
	/* --------------------- */

  w0 ^= RC2[0];

	block[0] = w0;
	block[1] = w1;
	block[2] = w2;
	block[3] = w3;

}  /* Round */
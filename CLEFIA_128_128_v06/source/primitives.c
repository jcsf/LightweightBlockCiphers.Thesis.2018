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
#include <string.h>

#include "constants.h"
#include "primitives.h"
#include "tables.h"

/*
 *
 * Cipher Primitives
 *
 */

void ClefiaGfn4(uint32_t *block, uint32_t *rk, int8_t rounds_minus_1) {
  uint8_t i;
  uint32_t temp;

	for(i = 0; i < rounds_minus_1; i++) {
		ClefiaF0Xor(block, rk[0]);
		ClefiaF1Xor(block + 2, rk[1]);
		rk += 2;

		/* Feistel Permutation */
		temp = block[0];
		block[0] = block[1];
		block[1] = block[2];
		block[2] = block[3];
		block[3] = temp;
	}

  /* Last Round */
	ClefiaF0Xor(block, rk[0]);
	ClefiaF1Xor(block + 2, rk[1]);
}

void ClefiaGfn4Inv(uint32_t *block, uint32_t* rk, int8_t rounds_minus_1) {
  uint8_t i;
  uint32_t temp;

	for(i = 0; i < rounds_minus_1; i++) {
		ClefiaF0Xor(block, rk[0]);
		ClefiaF1Xor(block + 2, rk[1]);
		rk -= 2;

		/* Feistel Permutation */
		temp = block[3];
		block[3] = block[2];
		block[2] = block[1];
		block[1] = block[0];
		block[0] = temp;
	}

  /* Last Round */
	ClefiaF0Xor(block, rk[0]);
	ClefiaF1Xor(block + 2, rk[1]);
}

void ClefiaF0Xor(uint32_t *slice, const uint32_t rk)
{
  uint32_t F0out, x1, x2, x3, x4;

  /* F0 */
  /* Key addition */
  F0out = *slice ^ rk;
  
  x1 = (uint8_t)(F0out);
  x2 = (uint8_t)(F0out >> 8);
  x3 = (uint8_t)(F0out >> 16);
  x4 = (uint8_t)(F0out >> 24);

  /*y[0] = fout & 0xFF;
  y[1] = (fout >> 8) & 0xFF;
  y[2] = (fout >> 16) & 0xFF;
  y[3] = (fout >> 24) & 0xFF;*/
  
  F0out = T0_F0[x1] ^ T1_F0[x2] ^ T2_F0[x3] ^ T3_F0[x4];

  slice[1] = slice[1] ^ F0out;
}

void ClefiaF1Xor(uint32_t *slice, const uint32_t rk)
{
  uint32_t F1out, x1, x2, x3, x4;

  /* F1 */
  /* Key addition */
  F1out = *slice ^ rk;
 
  x1 = (uint8_t)(F1out);
  x2 = (uint8_t)(F1out >> 8);
  x3 = (uint8_t)(F1out >> 16);
  x4 = (uint8_t)(F1out >> 24);
  
  /*y[0] = fout & 0xFF;
  y[1] = (fout >> 8) & 0xFF;
  y[2] = (fout >> 16) & 0xFF;
  y[3] = (fout >> 24) & 0xFF;*/

  F1out = T0_F1[x1] ^ T1_F1[x2] ^ T2_F1[x3] ^ T3_F1[x4];

  /* Xoring after F1 */
  slice[1] = slice[1] ^ F1out;
}
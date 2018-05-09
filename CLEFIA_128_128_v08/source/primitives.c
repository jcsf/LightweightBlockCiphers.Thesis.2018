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

	for(i = rounds_minus_1; i > 0; i--) {
		ClefiaF0Xor(block, rk[0])
		ClefiaF1Xor(block + 2, rk[1])
		rk += 2;

		/* Feistel Permutation */
		temp = block[0];
		block[0] = block[1];
		block[1] = block[2];
		block[2] = block[3];
		block[3] = temp;
	}

  	/* Last Round */
	ClefiaF0Xor(block, rk[0])
	ClefiaF1Xor(block + 2, rk[1])
}

void ClefiaGfn4Inv(uint32_t *block, uint32_t* rk, int8_t rounds_minus_1) {
  uint8_t i;
  uint32_t temp;

	for(i = rounds_minus_1; i > 0; i--) {
		ClefiaF0Xor(block, rk[0])
		ClefiaF1Xor(block + 2, rk[1])
		rk -= 2;

		/* Feistel Permutation */
		temp = block[3];
		block[3] = block[2];
		block[2] = block[1];
		block[1] = block[0];
		block[0] = temp;
	}

  /* Last Round */
	ClefiaF0Xor(block, rk[0])
	ClefiaF1Xor(block + 2, rk[1])
}
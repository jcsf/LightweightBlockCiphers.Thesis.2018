/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Dmitry Khovratovich <dmitry.khovratovich@uni.lu>
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

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t* data = (uint32_t*) block;
	uint32_t* rk = (uint32_t*) roundKeys;
	uint8_t i, j;

	// Go To the End of the Keys
	rk = rk + (NUMBER_OF_ROUNDS << 2) + 3; // rk = rk + (NUMBER_OF_ROUNDS * 4);

	j = 3;
	// Add Last Key
	for(i = 0; i < 4; i++) {
		data[j] = data[j] ^ *rk;
		rk -= 1;
		j -= 1;
	}

	uint32_t x0, x1, x2, x3, t0, t1, t2, t3, temp;

	// Rounds
	for(i = 0; i < NUMBER_OF_ROUNDS - 1; i++) {
		x0 = data[0];
		x1 = data[1];
		x2 = data[2];
		x3 = data[3];

		for(j = 0; j < 4; j++) {
			// Row
			t0 = (uint8_t)(x3);
			inv_T0(t0)
			t1 = (uint8_t)(x2 >> 8);
			inv_T1(t1)
			t2 = (uint8_t)(x1 >> 16);
			inv_T2(t2)
			t3 = (uint8_t)(x0 >> 24);
			inv_T3(t3)
			
			data[3-j] = (t0 ^ t1 ^ t2 ^ t3) ^ *rk;
			rk -= 1;

			// Permutations for next row
			temp = x3;
			x3 = x2;
			x2 = x1;
			x1 = x0;
			x0 = temp;
		}
	}

	// Last Round
	x0 = data[0];
	x1 = data[1];
	x2 = data[2];
	x3 = data[3];

	for(j = 0; j < 4; j++) {
		// Row
		t0 = (uint8_t)(x3);
		t0 = inv_Sbox[t0];
		t1 = (uint8_t)(x2 >> 8);
		t1 = inv_Sbox[t1];
		t2 = (uint8_t)(x1 >> 16);
		t2 = inv_Sbox[t2];
		t3 = (uint8_t)(x0 >> 24);
		t3 = inv_Sbox[t3];

		data[3-j] = ((t0) | (t1 << 8) | (t2 << 16) | (t3 << 24)) ^ *rk;
		rk -= 1;

		// Permutations for next row
		temp = x3;
		x3 = x2;
		x2 = x1;
		x1 = x0;
		x0 = temp;
	}
}

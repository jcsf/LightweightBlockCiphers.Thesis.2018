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

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t* data = (uint32_t*) block;
	uint32_t* rk = (uint32_t*) roundKeys;
	uint8_t i;

	register uint32_t x0, x1, x2, x3, t0, t1, t2, t3;
	register uint32_t data0, data1, data2, data3;
	
	data0 = data[0];
	data1 = data[1];
	data2 = data[2];
	data3 = data[3];

	// Add Initial Key
	data0 ^= rk[0];
	data1 ^= rk[1];
	data2 ^= rk[2];
	data3 ^= rk[3];
	rk += 4;

	// Rounds
	for(i = 0; i < NUMBER_OF_ROUNDS - 1; i++) {
		x0 = data0;
		x1 = data1;
		x2 = data2;
		x3 = data3;

		// First Row
		t0 = (uint8_t)(x0);
		T0(t0)
		t1 = (uint8_t)(x1 >> 8);
		T1(t1)
		t2 = (uint8_t)(x2 >> 16);
		T2(t2)
		t3 = (uint8_t)(x3 >> 24);
		T3(t3)
		
		data0 = (t0 ^ t1 ^ t2 ^ t3) ^ *rk;
		rk += 1;

		// Second Row
		t0 = (uint8_t)(x1);
		T0(t0)
		t1 = (uint8_t)(x2 >> 8);
		T1(t1)
		t2 = (uint8_t)(x3 >> 16);
		T2(t2)
		t3 = (uint8_t)(x0 >> 24);
		T3(t3)
		
		data1 = (t0 ^ t1 ^ t2 ^ t3) ^ *rk;
		rk += 1;

		// Third Row
		t0 = (uint8_t)(x2);
		T0(t0)
		t1 = (uint8_t)(x3 >> 8);
		T1(t1)
		t2 = (uint8_t)(x0 >> 16);
		T2(t2)
		t3 = (uint8_t)(x1 >> 24);
		T3(t3)
		
		data2 = (t0 ^ t1 ^ t2 ^ t3) ^ *rk;
		rk += 1;

		// Fourth Row
		t0 = (uint8_t)(x3);
		T0(t0)
		t1 = (uint8_t)(x0 >> 8);
		T1(t1)
		t2 = (uint8_t)(x1 >> 16);
		T2(t2)
		t3 = (uint8_t)(x2 >> 24);
		T3(t3)
		
		data3 = (t0 ^ t1 ^ t2 ^ t3) ^ *rk;
		rk += 1;
	}

	// Last Round

	// First Row
	t0 = (uint8_t)(data0);
	t0 = Sbox[t0];
	t1 = (uint8_t)(data1 >> 8);
	t1 = Sbox[t1];
	t2 = (uint8_t)(data2 >> 16);
	t2 = Sbox[t2];
	t3 = (uint8_t)(data3 >> 24);
	t3 = Sbox[t3];

	data[0] = ((t0) | (t1 << 8) | (t2 << 16) | (t3 << 24)) ^ *rk;
	rk += 1;

	// Second Row
	t0 = (uint8_t)(data1);
	t0 = Sbox[t0];
	t1 = (uint8_t)(data2 >> 8);
	t1 = Sbox[t1];
	t2 = (uint8_t)(data3 >> 16);
	t2 = Sbox[t2];
	t3 = (uint8_t)(data0 >> 24);
	t3 = Sbox[t3];

	data[1] = ((t0) | (t1 << 8) | (t2 << 16) | (t3 << 24)) ^ *rk;
	rk += 1;

	// Third Row
	t0 = (uint8_t)(data2);
	t0 = Sbox[t0];
	t1 = (uint8_t)(data3 >> 8);
	t1 = Sbox[t1];
	t2 = (uint8_t)(data0 >> 16);
	t2 = Sbox[t2];
	t3 = (uint8_t)(data1 >> 24);
	t3 = Sbox[t3];

	data[2] = ((t0) | (t1 << 8) | (t2 << 16) | (t3 << 24)) ^ *rk;
	rk += 1;

	// Fourth Row
	t0 = (uint8_t)(data3);
	t0 = Sbox[t0];
	t1 = (uint8_t)(data0 >> 8);
	t1 = Sbox[t1];
	t2 = (uint8_t)(data1 >> 16);
	t2 = Sbox[t2];
	t3 = (uint8_t)(data2 >> 24);
	t3 = Sbox[t3];

	data[3] = ((t0) | (t1 << 8) | (t2 << 16) | (t3 << 24)) ^ *rk;
}

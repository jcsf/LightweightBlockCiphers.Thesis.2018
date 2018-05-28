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
#include "primitives.h"

void subBytes(uint8_t* block) {
	uint8_t j;

	for(j = 0; j < BLOCK_SIZE; j++) {
		block[j] = Sbox[block[j]];
	}
}

void shiftRow(uint8_t* block, uint8_t shift) {
	uint8_t tmp[4];

	tmp[0] = block[0];
	tmp[1] = block[4];
	tmp[2] = block[8];
	tmp[3] = block[12];
	
	block[0] = tmp[(shift + 0) & 3];
	block[4] = tmp[(shift + 1) & 3];
	block[8] = tmp[(shift + 2) & 3];
	block[12] = tmp[(shift + 3) & 3];
}

void addKey(uint32_t* block32, uint32_t* roundKeys32) {
	block32[0] ^= roundKeys32[0];
	block32[1] ^= roundKeys32[1];
	block32[2] ^= roundKeys32[2];
	block32[3] ^= roundKeys32[3];
}

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t *block32 = (uint32_t*) block;
	uint32_t *roundKeys32 = (uint32_t*) roundKeys;
	uint8_t x0, x1, x2, x3;
	uint8_t i, j;

	// Add Initial Round Key
	addKey(block32, roundKeys32);
	roundKeys32 += 4;

	for(i = 1; i < NUMBER_OF_ROUNDS; i++) {	
		// SBox Layer
		subBytes(block);

		// ShiftRow Layer
		shiftRow(block + 1, 1);
		shiftRow(block + 2, 2);
		shiftRow(block + 3, 3);

		// MixColumns Layer
		for(j = 0; j < 4; j++) {
			uint8_t t = j << 2; // j * 4

			x0 = block[t];
			x1 = block[t + 1];
			x2 = block[t + 2];
			x3 = block[t + 3];

			// Fastest Version
			uint8_t Tmp = x0 ^ x1 ^ x2 ^ x3;
			
			block[t] ^= AESMul2(x0 ^ x1) ^ Tmp ;
			block[t + 1] ^= AESMul2(x1 ^ x2) ^ Tmp;
			block[t + 2] ^= AESMul2(x2 ^ x3) ^ Tmp;
			block[t + 3] ^= AESMul2(x3 ^ x0) ^ Tmp;
		}

		// Add Key
		addKey(block32, roundKeys32);
		roundKeys32 += 4;
	}

	// Last Round

	// SBox Layer
	subBytes(block);

	// ShiftRow Layer
	shiftRow(block + 1, 1);
	shiftRow(block + 2, 2);
	shiftRow(block + 3, 3);

	// Add Key
	addKey(block32, roundKeys32);
}

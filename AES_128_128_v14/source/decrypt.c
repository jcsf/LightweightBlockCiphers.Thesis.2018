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

void inv_subBytes(uint8_t* block) {
	uint8_t j;

	for(j = 0; j < BLOCK_SIZE; j++) {
		block[j] = inv_Sbox[block[j]];
	}
}

void inv_shiftRow(uint8_t* block, uint8_t shift) {
	uint8_t tmp[4];

	tmp[0] = block[0];
	tmp[1] = block[4];
	tmp[2] = block[8];
	tmp[3] = block[12];
	
	block[0] = tmp[(4 - shift + 0) & 3];
	block[4] = tmp[(4 - shift + 1) & 3];
	block[8] = tmp[(4 - shift + 2) & 3];
	block[12] = tmp[(4 - shift + 3) & 3];
}

void inv_addKey(uint32_t* block32, uint32_t* roundKeys32) {
	block32[0] ^= roundKeys32[0];
	block32[1] ^= roundKeys32[1];
	block32[2] ^= roundKeys32[2];
	block32[3] ^= roundKeys32[3];
}

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t *block32 = (uint32_t*) block;
	uint32_t *roundKeys32 = (uint32_t*) roundKeys;
	uint8_t x0, x1, x2, x3;
	uint8_t i, j;

	roundKeys32 += 10 << 2;

	// Inv Last Round

	// Add Key
	inv_addKey(block32, roundKeys32);
	roundKeys32 -= 4;

	// SBox Layer
	inv_subBytes(block);

	// ShiftRow Layer
	inv_shiftRow(block + 1, 1);
	inv_shiftRow(block + 2, 2);
	inv_shiftRow(block + 3, 3);

	for(i = 1; i < NUMBER_OF_ROUNDS; i++) {
		// Add Round Key
		inv_addKey(block32, roundKeys32);
		roundKeys32 -= 4;

		// Inv MixColumns Layer
		for(j = 0; j < 4; j++) {
			uint8_t t = j << 2; // j * 4

			x0 = block[t];
			x1 = block[t + 1];
			x2 = block[t + 2];
			x3 = block[t + 3];

			block[t] 	 = AESMul14(x0) ^ AESMul11(x1) ^ AESMul13(x2) ^ AESMul9(x3);
			block[t + 1] =  AESMul9(x0) ^ AESMul14(x1) ^ AESMul11(x2) ^ AESMul13(x3);
			block[t + 2] = AESMul13(x0) ^  AESMul9(x1) ^ AESMul14(x2) ^ AESMul11(x3);
			block[t + 3] = AESMul11(x0) ^ AESMul13(x1) ^  AESMul9(x2) ^ AESMul14(x3);
		}

		// Inv ShiftRow Layer
		inv_shiftRow(block + 1, 1);
		inv_shiftRow(block + 2, 2);
		inv_shiftRow(block + 3, 3);

		// Inv SBox Layer
		inv_subBytes(block);
	}

	// Add Initial Round Key
	inv_addKey(block32, roundKeys32);
}

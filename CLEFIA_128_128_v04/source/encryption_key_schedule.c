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

#include "cipher.h"
#include "constants.h"
#include "primitives.h"

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint32_t *k = (uint32_t*) key;
	uint32_t *rk = (uint32_t*) roundKeys;
	uint32_t con128[60];
	uint32_t lk[4];
	uint8_t i;

	/* generating CONi^(128) (0 <= i < 60, lk = 30) */
	const uint8_t iv[2] = {0x42U, 0x8aU}; /* cubic root of 2 */
	ClefiaConSet((uint8_t*)con128, iv, 30);

	/* GFN_{4,12} (generating L from K) */
	memcpy(lk, key, KEY_SIZE);

	/* ClefiaGfn4 */
	ClefiaGfn4(lk, con128, 11);
	uint32_t *rcon128 = con128 + (12 << 1); // NUMBER_OF_ROUNDS * 2 
	/* End ClefiaGfn4 */

	/* Initial Whitening Key (WK0, WK1) */
	rk[0] = k[0];
	rk[1] = k[1];

	rk += 2;

	for(i = 0; i < 9; i++) {
		rk[0] = lk[0] ^ rcon128[0];
		rk[1] = lk[1] ^ rcon128[1];
		rk[2] = lk[2] ^ rcon128[2];
		rk[3] = lk[3] ^ rcon128[3];
		
		if(i & 1) { // When "i" is Odd
			rk[0] ^= k[0];
			rk[1] ^= k[1];
			rk[2] ^= k[2];
			rk[3] ^= k[3];
		}

		uint8_t *doubleSwap_lk = (uint8_t *) lk;

		ClefiaDoubleSwap(doubleSwap_lk); /* Updating L (DoubleSwap function) */

		rk += 4;
		rcon128 += 4;
	}

	/* Final Whitening Key (WK2, WK3) */
	rk[0] = k[2];
	rk[1] = k[3];
}
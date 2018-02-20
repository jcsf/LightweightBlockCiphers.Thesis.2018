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

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint8_t *rk = roundKeys;
	const uint8_t *skey = key;

	const uint8_t iv[2] = {0x42U, 0x8aU}; /* cubic root of 2 */
	uint8_t lk[16];
	uint8_t con128[4 * 60];
	uint8_t i;

	/* generating CONi^(128) (0 <= i < 60, lk = 30) */
	ClefiaConSet(con128, iv, 30);
	/* GFN_{4,12} (generating L from K) */
	ClefiaGfn4(lk, skey, con128, 12);

	ByteCpy(rk, skey, 8); /* initial whitening key (WK0, WK1) */
	rk += 8;
	for(i = 0; i < 9; i++){ /* round key (RKi (0 <= i < 36)) */
		ByteXor(rk, lk, con128 + i * 16 + (4 * 24), 16);
		if(i % 2){
			ByteXor(rk, rk, skey, 16); /* Xoring K */
		}
		ClefiaDoubleSwap(lk); /* Updating L (DoubleSwap function) */
		rk += 16;
	}
	ByteCpy(rk, skey + 8, 8); /* final whitening key (WK2, WK3) */
}
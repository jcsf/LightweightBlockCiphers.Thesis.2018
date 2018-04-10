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

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	const uint32_t *rk = (uint32_t*) roundKeys;
	uint32_t *data = (uint32_t*) block;

	/* Initial Key Whitening */
	data[1] = data[1] ^ rk[0];
	data[3] = data[3] ^ rk[1];
	rk += 2;

	/* ClefiaGfn4 */
	uint8_t r;
	uint32_t temp;

	for(r = 0; r < NUMBER_OF_ROUNDS - 1; r++) {
		ClefiaF0Xor(data, rk[0]);
		ClefiaF1Xor(data + 2, rk[1]);
		rk += 2;

		/* Feistel Permutation */
		temp = data[0];
		data[0] = data[1];
		data[1] = data[2];
		data[2] = data[3];
		data[3] = temp;
	}

	ClefiaF0Xor(data, rk[0]);
	ClefiaF1Xor(data + 2, rk[1]);
	rk += 2;
	/* End ClefiaGfn4 */

	/* Final Key Whitening */
	data[1] = data[1] ^ rk[0];
	data[3] = data[3] ^ rk[1];
}
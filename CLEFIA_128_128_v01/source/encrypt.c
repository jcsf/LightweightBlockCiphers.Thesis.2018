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
	uint8_t *pt = block;
	const uint8_t *rk = roundKeys;
	uint8_t ct[BLOCK_SIZE], rin[BLOCK_SIZE], rout[BLOCK_SIZE];

	ByteCpy(rin,  pt,  16);

	ByteXor(rin + 4,  rin + 4,  rk + 0, 4); /* initial key whitening */
	ByteXor(rin + 12, rin + 12, rk + 4, 4);
	rk += 8;

	ClefiaGfn4(rout, rin, rk, NUMBER_OF_ROUNDS); /* GFN_{4,r} */

	ByteCpy(ct, rout, 16);
	ByteXor(ct + 4,  ct + 4,  rk + NUMBER_OF_ROUNDS * 8 + 0, 4); /* final key whitening */
	ByteXor(ct + 12, ct + 12, rk + NUMBER_OF_ROUNDS * 8 + 4, 4);

	//COPY BACK TO BLOCK
	ByteCpy(block, ct, 16);
}
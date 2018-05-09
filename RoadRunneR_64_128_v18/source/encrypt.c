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

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t i, key = 4;
	uint32_t *data = (uint32_t*) block, temp;
	uint32_t *rk = (uint32_t*) roundKeys;

	data[0] ^= rk[0];

	RRR_ROUND(block, roundKeys, &key, 12, 4)
	RRR_ROUND(block, roundKeys, &key, 11, 4)
	RRR_ROUND(block, roundKeys, &key, 10, 4)
	RRR_ROUND(block, roundKeys, &key, 9, 4)
	RRR_ROUND(block, roundKeys, &key, 8, 4)
	RRR_ROUND(block, roundKeys, &key, 7, 4)
	RRR_ROUND(block, roundKeys, &key, 6, 4)
	RRR_ROUND(block, roundKeys, &key, 5, 4)
	RRR_ROUND(block, roundKeys, &key, 4, 4)
	RRR_ROUND(block, roundKeys, &key, 3, 4)
	RRR_ROUND(block, roundKeys, &key, 2, 4)
	RRR_ROUND(block, roundKeys, &key, 1, 4)

	temp = data[0];
	data[0] = data[1] ^ rk[1];
	data[1] = temp;
}


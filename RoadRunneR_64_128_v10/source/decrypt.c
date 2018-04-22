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

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint8_t i, key = 8;
	uint32_t *data = (uint32_t*) block, temp;
	uint32_t *rk = (uint32_t*) roundKeys;

	data[0] ^= rk[1];

	uint8_t rounds = NUMBER_OF_ROUNDS + 1;

	for(i = 1;i < rounds; i++) {
		rrr_enc_dec_round(block, roundKeys, &key, i, 12);
	}

	temp = data[0];
	data[0] = data[1] ^ rk[0];
	data[1] = temp;
}


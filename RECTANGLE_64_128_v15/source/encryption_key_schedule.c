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

#define MUL4(x) ((x) << 2) // 4 * x


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint8_t key8[16];
	uint16_t *key16 = (uint16_t*)key8;
	uint32_t *key32 = (uint32_t*)key8;

	/* the master key can not be modified. */
	memcpy(key8, key, KEY_SIZE);

	uint8_t i;
	uint16_t *roundKeys16 = (uint16_t*)roundKeys;

	/* the first round keys */
	roundKeys16[0] = key16[0];
	roundKeys16[1] = key16[2];
	roundKeys16[2] = key16[4];
	roundKeys16[3] = key16[6];

	/* key schedule */
	uint8_t sbox0, sbox1, w0, w4, w8, w12;
	uint32_t temp;

	for (i = 1; i <= NUMBER_OF_ROUNDS; i++) {
		/* Change to 8 bits */
		w0 = key8[0];
		w4 = key8[4];
		w8 = key8[8];
		w12 = key8[12];

		/* S box */
		sbox1 = ~w4;
		sbox0 = sbox1 | w12;
		sbox0 ^= w0;
		w0 &= sbox1;
		sbox1 = w8 ^ w12;
		w0 ^= sbox1;
		w12 = w4 ^ w8;
		w4 = w8 ^ sbox0;
		sbox1 &= sbox0;
		w12 ^= sbox1;
		w8 = w0 | w12;
		w8 ^= sbox0;

		/* Back to 32 bits */
		key8[0] = w0;
		key8[4] = w4;
		key8[8] = w8;
		key8[12] = w12;
		
		/* Row */
		temp = key32[0];
		key32[0] = (temp << 8 | temp >> 24) ^ key32[1];
		key32[1] = key32[2];
		key32[2] = (key32[2] << 16 | key32[2] >> 16) ^ key32[3];
		key32[3] = temp;

		/* round const */
		*key8 ^= RC[i-1];

		/* store round key */
		sbox0 = MUL4(i);
		roundKeys16[sbox0] = key16[0];
		roundKeys16[sbox0+1] = key16[2];
		roundKeys16[sbox0+2] = key16[4];
		roundKeys16[sbox0+3] = key16[6];
	}
}
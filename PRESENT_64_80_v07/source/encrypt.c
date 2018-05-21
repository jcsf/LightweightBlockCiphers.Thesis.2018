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
#include "rotate.h"

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint64_t state = *(uint64_t*)block;
	uint64_t *roundKeys64 = (uint64_t*)roundKeys;
	uint64_t temp;
	uint8_t i, j;
	uint8_t sBoxValue, position;

	for (i = 0; i < 31; i++)
	{
		/* addRoundkey */
		state ^= roundKeys64[i];

		/* sBoxLayer */
		for (j = 0; j < 16; j++)
		{
			/* get lowest nibble */
			sBoxValue = state & 0xF;

			/* kill lowest nibble */
			state &= 0xFFFFFFFFFFFFFFF0; 

			/* put new value to lowest nibble (sBox) */
			state |= sBox4[sBoxValue];

			/* next(rotate by one nibble) */
			state = rotate4l_64(state); 
		}

		/* pLayer */
		temp = 0;
		for (j = 0; j < 63; j++)
		{
			/* arithmentic calculation of the p-Layer */
			position = (j << 4) % 63; // (j * 16) % 63

			/* result writing */
			temp |= ((state >> j) & 0x1) << position; 
		}
		state = temp | (state & 0x8000000000000000); // Add last bit (bit 63)
	}


	/* addRoundkey (Round 31) */
	*(uint64_t*)block = state ^ roundKeys64[31];
}

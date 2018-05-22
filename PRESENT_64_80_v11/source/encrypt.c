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

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t *state = (uint32_t*)block;
	uint32_t *roundKeys32 = (uint32_t*)roundKeys;
	register uint32_t state0, state1, temp0, temp1;
	register uint8_t i, j, val0, val1, shift0, shift1, shift2, shift3;

	state0 = state[0];
	state1 = state[1];

	for (i = 0; i < 31; i++)
	{
		/* addRoundkey */
		state0 ^= roundKeys32[i << 1];
		state1 ^= roundKeys32[(i << 1) + 1];

		/* sBoxLayer */
		for(j = 0; j < 4; j++)
		{
			val0 = state0 & 0xFF;
			val1 = state1 & 0xFF;

			state0 &= 0xFFFFFF00; 			
			state1 &= 0xFFFFFF00; 
			
			state0 |= sBox8[val0];
			state1 |= sBox8[val1];

			state0 = (state0 >> 8) | (state0 << 24);
			state1 = (state1 >> 8) | (state1 << 24);
		}
		
		/* pLayer */
		temp0 = 0; temp1 = 0;

		shift0 = 0;
		shift1 = 16;
		shift2 = 8;
		shift3 = 24;
		for(j = 0; j < 32; ) {
			temp0=temp0^(((state0>>j)&0x1) << shift0);
			temp0=temp0^(((state1>>j)&0x1) << shift2);
			j++;
			temp0=temp0^(((state0>>j)&0x1) << shift1);
			temp0=temp0^(((state1>>j)&0x1) << shift3);
			j++;
			temp1=temp1^(((state0>>j)&0x1) << shift0);
			temp1=temp1^(((state1>>j)&0x1) << shift2);
			j++;
			temp1=temp1^(((state0>>j)&0x1) << shift1);
			temp1=temp1^(((state1>>j)&0x1) << shift3);
			j++;

			shift0++;shift1++;shift2++;shift3++;
		}

		state0 = temp0;
		state1 = temp1;
	}


	/* addRoundkey (Round 31) */
	state[0] = state0 ^ roundKeys32[62];
	state[1] = state1 ^ roundKeys32[63];
}

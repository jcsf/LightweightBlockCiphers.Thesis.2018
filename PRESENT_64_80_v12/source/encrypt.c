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
	register uint8_t i, j, val0, val1;

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

		temp0=temp0^(((state0>>0)&0x1)<<0);
		temp0=temp0^(((state0>>1)&0x1)<<16);
		temp1=temp1^(((state0>>2)&0x1)<<0);
		temp1=temp1^(((state0>>3)&0x1)<<16);
		temp0=temp0^(((state0>>4)&0x1)<<1);
		temp0=temp0^(((state0>>5)&0x1)<<17);
		temp1=temp1^(((state0>>6)&0x1)<<1);
		temp1=temp1^(((state0>>7)&0x1)<<17);
		temp0=temp0^(((state0>>8)&0x1)<<2);
		temp0=temp0^(((state0>>9)&0x1)<<18);
		temp1=temp1^(((state0>>10)&0x1)<<2);
		temp1=temp1^(((state0>>11)&0x1)<<18);
		temp0=temp0^(((state0>>12)&0x1)<<3);
		temp0=temp0^(((state0>>13)&0x1)<<19);
		temp1=temp1^(((state0>>14)&0x1)<<3);
		temp1=temp1^(((state0>>15)&0x1)<<19);
		temp0=temp0^(((state0>>16)&0x1)<<4);
		temp0=temp0^(((state0>>17)&0x1)<<20);
		temp1=temp1^(((state0>>18)&0x1)<<4);
		temp1=temp1^(((state0>>19)&0x1)<<20);
		temp0=temp0^(((state0>>20)&0x1)<<5);
		temp0=temp0^(((state0>>21)&0x1)<<21);
		temp1=temp1^(((state0>>22)&0x1)<<5);
		temp1=temp1^(((state0>>23)&0x1)<<21);
		temp0=temp0^(((state0>>24)&0x1)<<6);
		temp0=temp0^(((state0>>25)&0x1)<<22);
		temp1=temp1^(((state0>>26)&0x1)<<6);
		temp1=temp1^(((state0>>27)&0x1)<<22);
		temp0=temp0^(((state0>>28)&0x1)<<7);
		temp0=temp0^(((state0>>29)&0x1)<<23);
		temp1=temp1^(((state0>>30)&0x1)<<7);
		temp1=temp1^(((state0>>31)&0x1)<<23);

		temp0=temp0^(((state1>>0)&0x1)<<8);
		temp0=temp0^(((state1>>1)&0x1)<<24);
		temp1=temp1^(((state1>>2)&0x1)<<8);
		temp1=temp1^(((state1>>3)&0x1)<<24);
		temp0=temp0^(((state1>>4)&0x1)<<9);
		temp0=temp0^(((state1>>5)&0x1)<<25);
		temp1=temp1^(((state1>>6)&0x1)<<9);
		temp1=temp1^(((state1>>7)&0x1)<<25);
		temp0=temp0^(((state1>>8)&0x1)<<10);
		temp0=temp0^(((state1>>9)&0x1)<<26);
		temp1=temp1^(((state1>>10)&0x1)<<10);
		temp1=temp1^(((state1>>11)&0x1)<<26);
		temp0=temp0^(((state1>>12)&0x1)<<11);
		temp0=temp0^(((state1>>13)&0x1)<<27);
		temp1=temp1^(((state1>>14)&0x1)<<11);
		temp1=temp1^(((state1>>15)&0x1)<<27);
		temp0=temp0^(((state1>>16)&0x1)<<12);
		temp0=temp0^(((state1>>17)&0x1)<<28);
		temp1=temp1^(((state1>>18)&0x1)<<12);
		temp1=temp1^(((state1>>19)&0x1)<<28);
		temp0=temp0^(((state1>>20)&0x1)<<13);
		temp0=temp0^(((state1>>21)&0x1)<<29);
		temp1=temp1^(((state1>>22)&0x1)<<13);
		temp1=temp1^(((state1>>23)&0x1)<<29);
		temp0=temp0^(((state1>>24)&0x1)<<14);
		temp0=temp0^(((state1>>25)&0x1)<<30);
		temp1=temp1^(((state1>>26)&0x1)<<14);
		temp1=temp1^(((state1>>27)&0x1)<<30);
		temp0=temp0^(((state1>>28)&0x1)<<15);
		temp0=temp0^(((state1>>29)&0x1)<<31);
		temp1=temp1^(((state1>>30)&0x1)<<15);
		temp1=temp1^(((state1>>31)&0x1)<<31);

		state0 = temp0;
		state1 = temp1;
	}


	/* addRoundkey (Round 31) */
	state[0] = state0 ^ roundKeys32[62];
	state[1] = state1 ^ roundKeys32[63];
}

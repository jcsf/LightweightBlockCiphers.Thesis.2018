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

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t *state = (uint32_t*)block;
	uint32_t *roundKeys32 = (uint32_t*)roundKeys;
	uint32_t temp0, temp1;
	uint8_t i, j, shift0, shift1, shift2, shift3;
	
	for (i = 31; i > 0; i--)
	{
		/* addRoundkey */
		state[0] ^= roundKeys32[i << 1];
		state[1] ^= roundKeys32[(i << 1) + 1];

		/* pLayer */
		temp0 = 0; temp1 = 0;

		shift0 = 0;
		shift1 = 8;
		shift2 = 16;
		shift3 = 24;
		for(j = 0; j < 32; ) {
			temp0=temp0^(((state[0]>>shift0)&0x1)<<j);
			temp1=temp1^(((state[0]>>shift1)&0x1)<<j);
			j++;

			temp0=temp0^(((state[0]>>shift2)&0x1)<<j);
			temp1=temp1^(((state[0]>>shift3)&0x1)<<j);
			j++;

			temp0=temp0^(((state[1]>>shift0)&0x1)<<j);
			temp1=temp1^(((state[1]>>shift1)&0x1)<<j);
			j++;

			temp0=temp0^(((state[1]>>shift2)&0x1)<<j);
			temp1=temp1^(((state[1]>>shift3)&0x1)<<j);
			j++;

			shift0++;shift1++;shift2++;shift3++;
		}

		/*
		temp0=temp0^(((state[0]>>0)&0x1)<<0);
		temp0=temp0^(((state[0]>>1)&0x1)<<4);
		temp0=temp0^(((state[0]>>2)&0x1)<<8);
		temp0=temp0^(((state[0]>>3)&0x1)<<12);
		temp0=temp0^(((state[0]>>4)&0x1)<<16);
		temp0=temp0^(((state[0]>>5)&0x1)<<20);
		temp0=temp0^(((state[0]>>6)&0x1)<<24);
		temp0=temp0^(((state[0]>>7)&0x1)<<28);
		
		temp1=temp1^(((state[0]>>8)&0x1)<<0);
		temp1=temp1^(((state[0]>>9)&0x1)<<4);
		temp1=temp1^(((state[0]>>10)&0x1)<<8);
		temp1=temp1^(((state[0]>>11)&0x1)<<12);
		temp1=temp1^(((state[0]>>12)&0x1)<<16);
		temp1=temp1^(((state[0]>>13)&0x1)<<20);
		temp1=temp1^(((state[0]>>14)&0x1)<<24);
		temp1=temp1^(((state[0]>>15)&0x1)<<28);

		temp0=temp0^(((state[0]>>16)&0x1)<<1);
		temp0=temp0^(((state[0]>>17)&0x1)<<5);
		temp0=temp0^(((state[0]>>18)&0x1)<<9);
		temp0=temp0^(((state[0]>>19)&0x1)<<13);
		temp0=temp0^(((state[0]>>20)&0x1)<<17);
		temp0=temp0^(((state[0]>>21)&0x1)<<21);
		temp0=temp0^(((state[0]>>22)&0x1)<<25);
		temp0=temp0^(((state[0]>>23)&0x1)<<29);

		temp1=temp1^(((state[0]>>24)&0x1)<<1);
		temp1=temp1^(((state[0]>>25)&0x1)<<5);
		temp1=temp1^(((state[0]>>26)&0x1)<<9);
		temp1=temp1^(((state[0]>>27)&0x1)<<13);
		temp1=temp1^(((state[0]>>28)&0x1)<<17);
		temp1=temp1^(((state[0]>>29)&0x1)<<21);
		temp1=temp1^(((state[0]>>30)&0x1)<<25);
		temp1=temp1^(((state[0]>>31)&0x1)<<29);



		temp0=temp0^(((state[1]>>0)&0x1)<<2);
		temp0=temp0^(((state[1]>>1)&0x1)<<6);
		temp0=temp0^(((state[1]>>2)&0x1)<<10);
		temp0=temp0^(((state[1]>>3)&0x1)<<14);
		temp0=temp0^(((state[1]>>4)&0x1)<<18);
		temp0=temp0^(((state[1]>>5)&0x1)<<22);
		temp0=temp0^(((state[1]>>6)&0x1)<<26);
		temp0=temp0^(((state[1]>>7)&0x1)<<30);

		temp1=temp1^(((state[1]>>8)&0x1)<<2);
		temp1=temp1^(((state[1]>>9)&0x1)<<6);
		temp1=temp1^(((state[1]>>10)&0x1)<<10);
		temp1=temp1^(((state[1]>>11)&0x1)<<14);
		temp1=temp1^(((state[1]>>12)&0x1)<<18);
		temp1=temp1^(((state[1]>>13)&0x1)<<22);
		temp1=temp1^(((state[1]>>14)&0x1)<<26);
		temp1=temp1^(((state[1]>>15)&0x1)<<30);

		temp0=temp0^(((state[1]>>16)&0x1)<<3);
		temp0=temp0^(((state[1]>>17)&0x1)<<7);
		temp0=temp0^(((state[1]>>18)&0x1)<<11);
		temp0=temp0^(((state[1]>>19)&0x1)<<15);
		temp0=temp0^(((state[1]>>20)&0x1)<<19);
		temp0=temp0^(((state[1]>>21)&0x1)<<23);
		temp0=temp0^(((state[1]>>22)&0x1)<<27);
		temp0=temp0^(((state[1]>>23)&0x1)<<31);

		temp1=temp1^(((state[1]>>24)&0x1)<<3);
		temp1=temp1^(((state[1]>>25)&0x1)<<7);
		temp1=temp1^(((state[1]>>26)&0x1)<<11);
		temp1=temp1^(((state[1]>>27)&0x1)<<15);
		temp1=temp1^(((state[1]>>28)&0x1)<<19);
		temp1=temp1^(((state[1]>>29)&0x1)<<23);
		temp1=temp1^(((state[1]>>30)&0x1)<<27);
		temp1=temp1^(((state[1]>>31)&0x1)<<31);
		*/

		state[0] = temp0;
		state[1] = temp1;
		
		/* sBoxLayer */
		for(j = 0; j < BLOCK_SIZE; j++)
		{
			block[j]=invsBox8[(block[j])];
		}
	}

	
	/* addRoundkey (Round 31) */
	state[0] ^= roundKeys32[0];
	state[1] ^= roundKeys32[1];
}
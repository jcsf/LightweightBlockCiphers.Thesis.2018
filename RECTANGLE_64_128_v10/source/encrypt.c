/*
 *
 * Chinese Academy of Sciences
 * State Key Laboratory of Information Security, 
 * Institute of Information Engineering
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2016 Chinese Academy of Sciences
 *
 * Written in 2016 by Luo Peng <luopeng@iie.ac.cn>,
 *					  Bao Zhenzhen <baozhenzhen@iie.ac.cn>,
 *					  Zhang Wentao <zhangwentao@iie.ac.cn>
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


void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t *block32 = (uint32_t*)block;
	uint32_t *roundKeys32 = (uint32_t*)roundKeys;

	uint32_t temprk = *block32;
	uint16_t w0 = (uint16_t)temprk;		// first line
	uint16_t w1 = (uint16_t)(temprk>>16);	// second line
	temprk = *(block32+1);
	uint16_t w2 = (uint16_t)temprk;		// third line
	uint16_t w3 = (uint16_t)(temprk>>16);	// forth line

	uint16_t sbox0, sbox1;
	uint8_t i;
	for ( i = 0; i < NUMBER_OF_ROUNDS; i++ ) {
		/* AddRoundKey */
		temprk = READ_ROUND_KEY_DOUBLE_WORD(*roundKeys32++);
		w0 ^= (uint16_t)temprk;
		w1 ^= (uint16_t)(temprk>>16);
		temprk = READ_ROUND_KEY_DOUBLE_WORD(*(roundKeys32++));
		w2 ^= (uint16_t)temprk;
		w3 ^= (uint16_t)(temprk>>16);
		/* SubColumn */	
		sbox1 = ~w1;
		sbox0 = sbox1 | w3;
		sbox0 ^= w0;
		w0 &= sbox1;
		sbox1 = w2 ^ w3;
		w0 ^= sbox1;
		w3 = w1 ^ w2;
		w1 = w2 ^ sbox0;
		sbox1 &= sbox0;
		w3 ^= sbox1;
		w2 = w0 | w3;
		w2 ^= sbox0;
		/* ShiftRow */
		w1 = (w1<<1  | w1 >> 15);
		w2 = (w2<<12 | w2 >> 4);
		w3 = (w3<<13 | w3 >> 3);
	}
	/* last round add key */
	temprk = READ_ROUND_KEY_DOUBLE_WORD(*roundKeys32++);
	w0 ^= (uint16_t)temprk;
	w1 ^= (uint16_t)(temprk>>16);
	temprk = READ_ROUND_KEY_DOUBLE_WORD(*roundKeys32++);
	w2 ^= (uint16_t)temprk;
	w3 ^= (uint16_t)(temprk>>16);
	/* store cipher text */
	*block32 = ((uint32_t)w1<<16) + w0;
	*(block32+1) = ((uint32_t)w3<<16) + w2;
}
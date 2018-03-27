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


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint8_t key8[10];
	/* the master key can not be modified. */
	uint8_t i;
	*((uint16_t*)key8) = *((uint16_t*)key);
	*((uint16_t*)key8+1) = *((uint16_t*)key+1);
	*((uint16_t*)key8+2) = *((uint16_t*)key+2);
	*((uint16_t*)key8+3) = *((uint16_t*)key+3);
	*((uint16_t*)key8+4) = *((uint16_t*)key+4);

	uint16_t *key16 = (uint16_t*)key8;
	uint16_t *roundKeys16 = (uint16_t*)roundKeys;

	/* the first round keys */
	roundKeys16[0] = key16[0];
	roundKeys16[1] = key16[1];
	roundKeys16[2] = key16[2];
	roundKeys16[3] = key16[3];

	/* key schedule */
	uint8_t sbox0, sbox1;
	uint8_t temp[4];
	uint16_t tempk0;
	for ( i = 1; i <= NUMBER_OF_ROUNDS; i++) {
		temp[0] = key8[0];
		temp[1] = key8[2];
		temp[2] = key8[4];
		temp[3] = key8[6];
		/* S box */
		sbox1 = ~key8[2];
		sbox0 = sbox1 | key8[6];
		sbox0 ^= key8[0];
		key8[0] &= sbox1;
		sbox1 = key8[4] ^ key8[6];
		key8[0] ^= sbox1;
		key8[6] = key8[2] ^ key8[4];
		key8[2] = key8[4] ^ sbox0;
		sbox1 &= sbox0;
		key8[6] ^= sbox1;
		key8[4] = key8[0] | key8[6];
		key8[4] ^= sbox0;
		/* just change 4-bit*/
		key8[0] = (key8[0]&0x0f) ^ (temp[0]&0xf0);
		key8[2] = (key8[2]&0x0f) ^ (temp[1]&0xf0);
		key8[4] = (key8[4]&0x0f) ^ (temp[2]&0xf0);
		key8[6] = (key8[6]&0x0f) ^ (temp[3]&0xf0);
		/* row */
		tempk0 = *(key16);
		*(key16) = *(key16+1);
		*(key16+1) = *(key16+2);
		*(key16+2) = *(key16+3);
		*(key16+3) = *(key16+4);
		*(key16+4) = tempk0;
		*(key16) ^= ((tempk0<<8)|(tempk0>>8));
		tempk0 = *(key16+2);
		*(key16+3) ^= ((tempk0<<12)|(tempk0>>4));
		/* round const */
		*key8 ^= READ_ROM_DATA_BYTE(RC[i-1]);
		/* store round key */
		roundKeys16[4*i] = key16[0];
		roundKeys16[4*i+1] = key16[1];
		roundKeys16[4*i+2] = key16[2];
		roundKeys16[4*i+3] = key16[3];
	}
}
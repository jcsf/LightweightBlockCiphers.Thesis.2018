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
	uint8_t i, temp[4] = {0}, j = 4;

	for(i=0;i<4;i++) {
		block[i] ^= READ_ROUND_KEY_BYTE(roundKeys[i]);
	}

	for(i=NUMBER_OF_ROUNDS; i>0; i--){
		rrr_enc_dec_round(block,roundKeys + j,i);
		j += 12;
	}
	
	memcpy(temp, block, 4);

	for(i=0;i<4;i++) {
		block[i] = block[i+4]^READ_ROUND_KEY_BYTE(roundKeys[148 + i]);
	}
	
	memcpy(block+4, temp, 4);
}


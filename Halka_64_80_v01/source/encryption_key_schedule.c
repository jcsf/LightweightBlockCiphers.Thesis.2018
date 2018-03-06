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


void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    uint8_t keystate[KEY_SIZE], tempks[KEY_SIZE];
    uint8_t i, j;

	memcpy(keystate, key, KEY_SIZE);

	uint8_t rounds_1 = NUMBER_OF_ROUNDS + 1;

    for (i = 0; i < rounds_1; i++)
	{
		for(j = 0; j < BLOCK_SIZE; j++)
		{
			//roundkey[i][j]=keystate[j+2];
            roundKeys[MATRIX_TO_ARRAY(i, j)] = keystate[j+2];
		}

		for (j = 0; j < KEY_SIZE; j++)
		{
			tempks[j]=keystate[(j+3)%10];
			tempks[j]=(tempks[j]<<1)^(keystate[(j+2)%10]>>7);
		}

		tempks[9]=S_BOX[tempks[9]]; //S-box

		tempks[2]=(uint8_t) (tempks[2]^(((i+1) & 30) >> 1)); //Round counter
		tempks[1]=(uint8_t) (tempks[1]^(((i+1)&1)<<7)); //Round counter

		memcpy(keystate, tempks, KEY_SIZE);
	}
}

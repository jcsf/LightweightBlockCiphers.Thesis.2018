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
#include "primitives.h"

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	register uint32_t *rk = (uint32_t *)roundKeys;
    register uint32_t rightSlice = ((uint32_t *)block)[0];
    register uint32_t leftSlice = ((uint32_t *)block)[1];
    register uint8_t r;

    rk += NUMBER_OF_ROUNDS-1;

    rightSlice = rightSlice ^ leftSlice;

    for (r = NUMBER_OF_ROUNDS - 1; r > 0; r--)
    {
		/*rightSlice = rightSlice ^ leftSlice;
        rightSlice = ror(rightSlice, BETA);

        leftSlice = leftSlice ^ *rk;
        leftSlice = leftSlice - rightSlice;
        leftSlice = rol(leftSlice, ALPHA);
        rk -= 1;*/

        leftSlice = leftSlice ^ *rk;
        leftSlice = leftSlice - ror(rightSlice, BETA);
        leftSlice = rol(leftSlice, ALPHA);

        rk -= 1;

        rightSlice =  ror(rightSlice, BETA) ^ leftSlice;
    }

    leftSlice = leftSlice ^ *rk;
    leftSlice = leftSlice - ror(rightSlice, BETA);
    
    ((uint32_t *)block)[0] = ror(rightSlice, BETA);
    ((uint32_t *)block)[1] = rol(leftSlice, ALPHA);;
}

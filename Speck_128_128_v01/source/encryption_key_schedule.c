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

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint64_t *mk = (uint64_t *)key; /* Main Key */
	uint64_t *rk = (uint64_t *)roundKeys;
    uint64_t l[NUMBER_OF_ROUNDS + NUMBER_KEYWORDS];

	uint8_t r;

	l[0] = mk[1];
	
	rk[0] = mk[0];
    for (r = 0; r < NUMBER_OF_ROUNDS-1; r++)
    {
		l[r+NUMBER_KEYWORDS-1] = (ror(l[r], ALPHA) + rk[r]) ^ r;
		rk[r+1] = rol(rk[r], BETA) ^ l[r+NUMBER_KEYWORDS-1];
    }
}

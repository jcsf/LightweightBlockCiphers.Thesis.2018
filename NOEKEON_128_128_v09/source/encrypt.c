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

#define round(state, k, RC)\
{\
	state[0] ^= RC; \
	THETA(k, state) \
	PI1(state) \
	GAMMA(state) \
	PI2(state) \
}

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t const *k = (uint32_t*) roundKeys;
	uint32_t *state = (uint32_t*) block;

	round(state, k, 0x80)
	round(state, k, 0x1b)
	round(state, k, 0x36)
	round(state, k, 0x6c)
	round(state, k, 0xd8)
	round(state, k, 0xab)
	round(state, k, 0x4d)
	round(state, k, 0x9a)
	round(state, k, 0x2f)
	round(state, k, 0x5e)
	round(state, k, 0xbc)
	round(state, k, 0x63)
	round(state, k, 0xc6)
	round(state, k, 0x97)
	round(state, k, 0x35)
	round(state, k, 0x6a)

	state[0] ^= 0xd4;
	THETA(k, state)
}
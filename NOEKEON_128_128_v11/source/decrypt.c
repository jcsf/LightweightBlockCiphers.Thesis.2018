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


void Decrypt(uint8_t *block, uint8_t *roundKeys) {
	uint32_t key[4];
	register uint32_t k0, k1, k2, k3;
	register uint32_t temp0, temp1;

	k0 = ((uint32_t*) roundKeys)[0];
	k1 = ((uint32_t*) roundKeys)[1];
	k2 = ((uint32_t*) roundKeys)[2];
	k3 = ((uint32_t*) roundKeys)[3];
  
	THETA(k0, k1, k2, k3, 0, 0, 0, 0, temp0, temp1)

	key[0] = k0;
	key[1] = k1;
	key[2] = k2;
	key[3] = k3;

	CommonLoop((uint32_t*)block, key, NullVector, RC);
}

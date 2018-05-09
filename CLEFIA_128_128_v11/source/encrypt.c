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

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	register uint32_t *rk = (uint32_t*) roundKeys;
	uint32_t *data = (uint32_t*) block;
	register uint32_t temp;
	register uint32_t x0, x1, x2, x3;
	register uint32_t Fout, y0, y1, y2, y3;

	x0 = data[0];
	x1 = data[1];
	x2 = data[2];
	x3 = data[3];

	/* Initial Key Whitening */
	x1 ^= rk[0];
	x3 ^= rk[1];
	rk += 2;

	/* ClefiaGfn4 */
	ClefiaGfn4(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk)
	/* End ClefiaGfn4 */

	/* Final Key Whitening */
	x1 ^= rk[0];
	x3 ^= rk[1];

	data[0] = x0;
	data[1] = x1;
	data[2] = x2;
	data[3] = x3;
}
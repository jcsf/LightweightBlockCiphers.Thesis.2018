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

#include "constants.h"
#include "primitives.h"
#include "tables.h"

/*
 *
 * Cipher Primitives
 *
 */
void ClefiaGfn4(uint32_t *block, register uint32_t *rk, int8_t rounds_minus_1) {
	register uint8_t i;
	register uint32_t temp;
	register uint32_t x0, x1, x2, x3;
	register uint32_t Fout, y0, y1, y2, y3;

	x0 = block[0];
	x1 = block[1];
	x2 = block[2];
	x3 = block[3];

	for(i = rounds_minus_1; i > 0; i--) {
		ClefiaF0Xor(x0, x1, rk[0], y0, y1, y2, y3, Fout)
		ClefiaF1Xor(x2, x3, rk[1], y0, y1, y2, y3, Fout)
		rk += 2;

		/* Feistel Permutation */
		temp = x0;
		x0 = x1;
		x1 = x2;
		x2 = x3;
		x3 = temp;
	}

  	/* Last Round */
	ClefiaF0Xor(x0, x1, rk[0], y0, y1, y2, y3, Fout)
	ClefiaF1Xor(x2, x3, rk[1], y0, y1, y2, y3, Fout)

	block[0] = x0;
	block[1] = x1;
	block[2] = x2;
	block[3] = x3;
}

void ClefiaGfn4Inv(uint32_t *block, register uint32_t* rk, int8_t rounds_minus_1) {
	register uint8_t i;
	register uint32_t temp;
	register uint32_t x0, x1, x2, x3;
	register uint32_t Fout, y0, y1, y2, y3;

	x0 = block[0];
	x1 = block[1];
	x2 = block[2];
	x3 = block[3];

	for(i = rounds_minus_1; i > 0; i--) {
		ClefiaF0Xor(x0, x1, rk[0], y0, y1, y2, y3, Fout)
		ClefiaF1Xor(x2, x3, rk[1], y0, y1, y2, y3, Fout)
		rk -= 2;

		/* Feistel Permutation */
		temp = x3;
		x3 = x2;
		x2 = x1;
		x1 = x0;
		x0 = temp;
	}

  	/* Last Round */
	ClefiaF0Xor(x0, x1, rk[0], y0, y1, y2, y3, Fout)
	ClefiaF1Xor(x2, x3, rk[1], y0, y1, y2, y3, Fout)

	block[0] = x0;
	block[1] = x1;
	block[2] = x2;
	block[3] = x3;
}
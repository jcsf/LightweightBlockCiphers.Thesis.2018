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
	uint16_t* x = (uint16_t*) block;
	/*uint16_t k[][2*ROUNDS_PER_STEPS] = (uint16_t**) roundKeys;*/
	uint16_t* k = (uint16_t*) roundKeys;

	uint8_t s, r, b;

	s=0; b=0; r=0;
	for (s=0 ; s<N_STEPS ; s++)
	{
		for (b=0 ; b<N_BRANCHES ; b++)
		{
			for (r=0 ; r<ROUNDS_PER_STEPS ; r++)
			{
				/*x[2*b  ] ^= k[N_BRANCHES*s + b][2*r    ];
				x[2*b+1] ^= k[N_BRANCHES*s + b][2*r + 1];*/
				x[2*b  ] ^= k[MATRIX_TO_ARRAY(N_BRANCHES*s + b, 2*r)];
				x[2*b+1] ^= k[MATRIX_TO_ARRAY(N_BRANCHES*s + b, 2*r + 1)];
				A(x + 2*b, x + 2*b+1);
			}
		}
		L(x);
	}
	
	for (b=0 ; b<N_BRANCHES ; b++)
	{
		/*x[2*b  ] ^= k[N_BRANCHES*N_STEPS][2*b  ];
		x[2*b+1] ^= k[N_BRANCHES*N_STEPS][2*b+1];*/
		x[2*b  ] ^= k[MATRIX_TO_ARRAY(N_BRANCHES*N_STEPS, 2*b)];
		x[2*b+1] ^= k[MATRIX_TO_ARRAY(N_BRANCHES*N_STEPS,2*b+1)];
	}
}
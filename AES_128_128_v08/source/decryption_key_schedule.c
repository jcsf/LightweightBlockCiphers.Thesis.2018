/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Dmitry Khovratovich <dmitry.khovratovich@uni.lu>
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

#include "key_schedule.h"
#include "constants.h"


void RunDecryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint32_t* rk = (uint32_t*)roundKeys;
	uint8_t* rkTemp;
	uint32_t x0, x1, x2, x3;
	uint8_t i;	

	KeySchedule(key, roundKeys);
	
	for (i = 4; i < 40; ++i)
	{
		rkTemp = roundKeys + (i << 2); // i * 4
		x0 = rkTemp[0];
		x0 = inv_MC0[x0];
		x1 = rkTemp[1];
		x1 = inv_MC1[x1];
		x2 = rkTemp[2];
		x2 = inv_MC2[x2];
		x3 = rkTemp[3];
		x3 = inv_MC3[x3];
		rk[i] = x0 ^ x1 ^ x2 ^ x3;
	}
}

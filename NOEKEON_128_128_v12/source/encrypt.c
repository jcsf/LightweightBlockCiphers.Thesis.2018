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

#define round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, RC)\
{ \
	w0 ^= RC; \
	\
	/* ------ THETA(w, k) -------- */ \
	THETA(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1) \
	/* --------------------- */ \
	\
	/* ------ PI1 -------- */ \
	PI1(w0, w1, w2, w3) \
	/* ------------------- */ \
	\
	/* ------ GAMMA -------- */ \
	GAMMA(w0, w1, w2, w3, temp0) \
	/* --------------------- */ \
	\
	/* ------ PI2 -------- */ \
	PI2(w0, w1, w2, w3) \
	/* ------------------- */ \
}

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	register uint8_t i;
	register uint32_t w0, w1, w2, w3;
	register uint32_t k0, k1, k2, k3;
	register uint32_t temp0, temp1;

	w0 = ((uint32_t*) block)[0];
	w1 = ((uint32_t*) block)[1];
	w2 = ((uint32_t*) block)[2];
	w3 = ((uint32_t*) block)[3];

	k0 = ((uint32_t*) roundKeys)[0];
	k1 = ((uint32_t*) roundKeys)[1];
	k2 = ((uint32_t*) roundKeys)[2];
	k3 = ((uint32_t*) roundKeys)[3];

	round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, 0x80)
	round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, 0x1b)
	round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, 0x36)
	round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, 0x6c)
	round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, 0xd8)
	round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, 0xab)
	round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, 0x4d)
	round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, 0x9a)
	round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, 0x2f)
	round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, 0x5e)
	round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, 0xbc)
	round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, 0x63)
	round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, 0xc6)
	round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, 0x97)
	round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, 0x35)
	round(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1, 0x6a)
	
	w0 ^= 0xd4;
	
	/* ------ THETA(w, k) -------- */
	THETA(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1)
	/* --------------------- */

	((uint32_t*) block)[0] = w0;
	((uint32_t*) block)[1] = w1;
	((uint32_t*) block)[2] = w2;
	((uint32_t*) block)[3] = w3;
}
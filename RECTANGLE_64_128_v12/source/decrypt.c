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

#define round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3)\
{\
	/* AddRoundKey */ \
	block32[0] ^= roundKeys32[0]; \
	block32[1] ^= roundKeys32[1]; \
	roundKeys32 -= 2; \
	\
	/* Change to 16 bits */ \
	w0 = (uint16_t)block32[0]; \
	w1 = (uint16_t)(block32[0]>>16); \
	w2 = (uint16_t)block32[1]; \
	w3 = (uint16_t)(block32[1]>>16); \
	\
	/* Inverse ShiftRow */ \
	w1 = (w1>>1  | w1 << 15); \
	w2 = (w2>>12 | w2 << 4); \
	w3 = (w3>>13 | w3 << 3); \
	\
	/* Inverse SBox */ \
	sbox2 = w0 ^ w1; \
	sbox0 = w0 | w3; \
	sbox0 ^= w2; \
	w2 = w1 ^ sbox0; \
	sbox1 = w0 & sbox0; \
	sbox1 ^= w3; \
	w1 = sbox1 ^ w2; \
	sbox3 = ~w1; \
	sbox1 = sbox0 | sbox3; \
	w3 = sbox1 ^ sbox2; \
	sbox1 = w3 | sbox3; \
	w0 = sbox0 ^ sbox1; \
	\
	/* Back to 32 bits */ \
	block32[0] = w0 | (w1 << 16); \
	block32[1] = w2 | (w3 << 16); \
}
void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t *block32 = (uint32_t*)block;
	uint32_t *roundKeys32 = (uint32_t*)roundKeys;
	
	uint16_t w0, w1, w2, w3;
	uint16_t sbox0, sbox1, sbox2, sbox3;

	// point to the start address of round 26
	roundKeys32 += 50;

	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);
	round(block32, roundKeys32, w0, w1, w2, w3, sbox, sbox1, sbox2, sbox3);

	/* Last Round Add Key */
	block32[0] ^= roundKeys32[0];
	block32[1] ^= roundKeys32[1];
}
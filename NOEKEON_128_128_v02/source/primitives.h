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

#ifndef PRIMITIVES_H
#define PRIMITIVES_H

#include "data_types.h"
#include "constants.h"

/*
 *
 * Cipher primitives
 *
 */

#define T8(x)   ((x) & ONE8)
#define T16(x)  ((x) & ONE16)
#define T32(x)  ((x) & ONE32)

#define RC1ENCRYPTSTART  T8 (0x80)
#define RC2DECRYPTSTART  T8 (0xD4) 

/*
 * U8TO32_BIG(c) returns the 32-bit value stored in big-endian convention
 * in the unsigned char array pointed to by c.
 */
#define U8TO32_BIG(c)  (((uint32_t)T8(*(c)) << 24) | ((uint32_t)T8(*((c) + 1)) << 16) |\
                       ((uint32_t)T8(*((c) + 2)) << 8) | ((uint32_t)T8(*((c) + 3))))

/*
 * U8TO32_LITTLE(c) returns the 32-bit value stored in little-endian convention
 * in the unsigned char array pointed to by c.
 */
#define U8TO32_LITTLE(c)  (((uint32_t)T8(*(c))) | ((uint32_t)T8(*((c) + 1)) << 8) |\
                      (uint32_t)T8(*((c) + 2)) << 16) | ((uint32_t)T8(*((c) + 3)) << 24))

/*
 * U8TO32_BIG(c, v) stores the 32-bit-value v in big-endian convention
 * into the unsigned char array pointed to by c.
 */
#define U32TO8_BIG(c, v)    do { \
		uint32_t x = (v); \
		uint8_t *d = (c); \
		d[0] = T8(x >> 24); \
		d[1] = T8(x >> 16); \
		d[2] = T8(x >> 8); \
		d[3] = T8(x); \
	} while (0)

/*
 * U8TO32_LITTLE(c, v) stores the 32-bit-value v in little-endian convention
 * into the unsigned char array pointed to by c.
 */
#define U32TO8_LITTLE(c, v)    do { \
		uint32_t x = (v); \
		uint8_t *d = (c); \
		d[0] = T8(x); \
		d[1] = T8(x >> 8); \
		d[2] = T8(x >> 16); \
		d[3] = T8(x >> 24); \
	} while (0)

/*
 * ROTL32(v, n) returns the value of the 32-bit unsigned value v after
 * a rotation of n bits to the left. It might be replaced by the appropriate
 * architecture-specific macro.
 *
 * It evaluates v and n twice.
 *
 * The compiler might emit a warning if n is the constant 0. The result
 * is undefined if n is greater than 31.
 */
#define ROTL32(v, n)   (T32((v) << (n)) | ((v) >> (32 - (n))))

/* Cipher Function Primitives */
extern void Theta (uint32_t const * const k, uint32_t * const a);
extern void Pi1(uint32_t * const a);
extern void Pi2(uint32_t * const a);
extern void Gamma(uint32_t * const a);
extern void Round (uint32_t const * const k, uint32_t * const a, uint8_t const RC1, uint8_t const RC2);
extern void RCShiftRegFwd (uint8_t * const RC);
extern void RCShiftRegBwd (uint8_t * const RC);
extern void CommonLoop (uint32_t const * const k, uint32_t * const a, uint8_t RC1, uint8_t RC2);

#endif /* PRIMITIVES_H */

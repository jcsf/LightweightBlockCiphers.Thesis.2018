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
#define PRIMITITVES_H

#define ROTL(x)   (((x)<<1)|((x)>>7))

#define RRR_SBOX(x0, x1, x2, x3) \
{ \
	register uint8_t temp = x3; \
	x3 &= x2; \
	x3 ^= x1; \
	x1 |= x2; \
	x1 ^= x0; \
	x0 &= x3; \
	x0 ^= temp; \
	temp &= x1; \
	x2 ^= temp; \
}

#define RRR_L(x) \
{ \
	register uint8_t temp = x; \
	temp = ROTL(temp); \
	temp ^= x; \
	temp = ROTL(temp); \
	x ^= temp; \
}

#define RRR_SLK(data, roundKey) \
{ \
	register uint8_t x0, x1, x2, x3; \
	x0 = data[0]; \
	x1 = data[1]; \
	x2 = data[2]; \
	x3 = data[3]; \
	\
	RRR_SBOX(x0, x1, x2, x3); \
	\
	uint8_t *rk = roundKey; \
	\
	RRR_L(x0); \
	x0 ^= READ_ROUND_KEY_BYTE(rk[0]); \
	\
	RRR_L(x1); \
	x1 ^= READ_ROUND_KEY_BYTE(rk[1]); \
	\
	RRR_L(x2); \
	x2 ^= READ_ROUND_KEY_BYTE(rk[2]); \
	\
	RRR_L(x3); \
	x3 ^= READ_ROUND_KEY_BYTE(rk[3]); \
	\
	data[0] = x0; \
	data[1] = x1; \
	data[2] = x2; \
	data[3] = x3; \
	\
}

#define RRR_SBOX_REG(data) \
{ \
	register uint8_t x0, x1, x2, x3; \
	x0 = data[0]; \
	x1 = data[1]; \
	x2 = data[2]; \
	x3 = data[3]; \
	\
	register uint8_t temp = x3; \
	x3 &= x2; \
	x3 ^= x1; \
	x1 |= x2; \
	x1 ^= x0; \
	x0 &= x3; \
	x0 ^= temp; \
	temp &= x1; \
	x2 ^= temp; \
	\
	data[0] = x0; \
	data[1] = x1; \
	data[2] = x2; \
	data[3] = x3; \
	\
}

#define RRR_ROUND(block, roundKey, round) \
{ \
	uint32_t temp; \
	\
	temp = ((uint32_t*)block)[0]; \
	\
	RRR_SLK(block,(roundKey)) \
	RRR_SLK(block,(roundKey)+4) \
	block[3] ^= round; \
	RRR_SLK(block,(roundKey)+8) \
	RRR_SBOX_REG(block) \
	\
	((uint32_t*)block)[0] ^= ((uint32_t*)block)[1]; \
	((uint32_t*)block)[1] = temp; \
}

#endif /* PRIMITIVES_H */


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

#define RRR_SBOX(data) \
{ \
	uint8_t temp = data[3]; \
	data[3] &= data[2]; \
	data[3] ^= data[1]; \
	data[1] |= data[2]; \
	data[1] ^= data[0]; \
	data[0] &= data[3]; \
	data[0] ^= temp; \
	temp &= data[1]; \
	data[2] ^= temp; \
}

#define RRR_L(data) \
{ \
	uint8_t temp = *(data); \
	temp = ROTL(temp); \
	temp ^= *(data); \
	temp = ROTL(temp); \
	*(data) ^= temp; \
}

#define RRR_SLK(data, roundKey) \
{ \
	uint8_t i; \
	uint8_t *rk = roundKey; \
	RRR_SBOX(data); \
	for(i = 0; i < 4; i++){ \
		RRR_L(data + i); \
		data[i] ^= READ_ROUND_KEY_BYTE(rk[i]); \
	} \
}

#define RRR_ROUND(block, roundKey, key, round, mode) \
{ \
	uint32_t temp; \
	\
	temp = ((uint32_t*)block)[0]; \
	\
	RRR_SLK(block,(roundKey) + *(key)); \
	*(key) = (*(key)+ 4) & 15; /* (key + 4) % 16 */ \
	RRR_SLK(block,(roundKey) + *(key)); \
	*(key) = (*(key)+ 4) & 15; /* (key + 4) % 16 */ \
	block[3] ^= round; \
	RRR_SLK(block,(roundKey) + *(key)); \
	*(key) = (*(key) + mode) & 15; /* Mode depends on encryption and decryption (+4 for encryption / +12 for decryption) */ \
	RRR_SBOX(block); \
	\
	((uint32_t*)block)[0] ^= ((uint32_t*)block)[1]; \
	((uint32_t*)block)[1] = temp; \
}

#endif /* PRIMITIVES_H */


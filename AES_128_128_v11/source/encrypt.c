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

#include "cipher.h"
#include "constants.h"


#define add_key(x, y0, y1, y2, y3, keys) \
{ \
	y0 = ((uint32_t *)x)[0] ^ READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)keys)[0]); \
	y1 = ((uint32_t *)x)[1] ^ READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)keys)[1]); \
	y2 = ((uint32_t *)x)[2] ^ READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)keys)[2]); \
	y3 = ((uint32_t *)x)[3] ^ READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)keys)[3]); \
}


#define last_round(x0, x1, x2, x3, output, keys, r) \
{ \
	uint32_t  t0, t1, t2, t3;    \
	uint32_t  t4, t5, t6, t7;    \
	uint32_t  t8, t9, t10, t11;  \
	uint32_t  t12, t13, t14, t15; \
	\
	t0 = (uint8_t)(x0);        \
	output[0] = READ_SBOX_BYTE(Sbox[t0]); \
	t7 = (uint8_t)((x0) >> 24);  \
	output[7] = READ_SBOX_BYTE(Sbox[t7]); \
	t10 = (uint8_t)((x0) >> 16);   \
	output[10] = READ_SBOX_BYTE(Sbox[t10]); \
	t13 = (uint8_t)((x0) >> 8);    \
	output[13] = READ_SBOX_BYTE(Sbox[t13]); \
	\
	t1 = (uint8_t)((x1) >> 8);   \
	output[1] = READ_SBOX_BYTE(Sbox[t1]); \
	t4 = (uint8_t)(x1);        \
	output[4] = READ_SBOX_BYTE(Sbox[t4]); \
	t11 = (uint8_t)((x1) >> 24);     \
	output[11] = READ_SBOX_BYTE(Sbox[t11]); \
	t14 = (uint8_t)((x1) >> 16);     \
	output[14] = READ_SBOX_BYTE(Sbox[t14]); \
	\
	t2 = (uint8_t)((x2) >> 16);  \
	output[2] = READ_SBOX_BYTE(Sbox[t2]); \
	t5 = (uint8_t)((x2) >> 8);   \
	output[5] = READ_SBOX_BYTE(Sbox[t5]); \
	t8 = (uint8_t)(x2);            \
	output[8] = READ_SBOX_BYTE(Sbox[t8]); \
	t15 = (uint8_t)((x2) >> 24);     \
	output[15] = READ_SBOX_BYTE(Sbox[t15]); \
	\
	t3 = (uint8_t)((x3) >> 24);  \
	output[3] = READ_SBOX_BYTE(Sbox[t3]); \
	t6 = (uint8_t)((x3) >> 16);  \
	output[6] = READ_SBOX_BYTE(Sbox[t6]); \
	t9 = (uint8_t)((x3) >> 8);       \
	output[9] = READ_SBOX_BYTE(Sbox[t9]);     \
	t12 = (uint8_t)(x3);           \
	output[12] = READ_SBOX_BYTE(Sbox[t12]);   \
	((uint32_t *)output)[0] ^= READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)keys)[4 * r]); \
	((uint32_t *)output)[1] ^= READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)keys)[4 * r + 1]); \
	((uint32_t *)output)[2] ^= READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)keys)[4 * r + 2]); \
	((uint32_t *)output)[3] ^= READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)keys)[4 * r + 3]); \
}


#define round(x0, x1, x2, x3, y0, y1, y2, y3, keys, r) \
{ \
	uint32_t  t0, t1, t2, t3;    \
	uint32_t  t4, t5, t6, t7;    \
	uint32_t  t8, t9, t10, t11;  \
	uint32_t  t12, t13, t14, t15; \
	\
	t0 = (uint8_t)(x0);      \
	T0(t0) \
	t1 = (uint8_t)((x1) >> 8); \
	T1(t1) \
	t1 = t1 ^ t0; \
	t2 = (uint8_t)((x2) >> 16);     \
	T2(t2) \
	t2 = t2 ^ t1; \
	t3 = (uint8_t)((x3) >> 24);     \
	T3(t3) \
	t3 = t3 ^ t2; \
	(y0) = t3 ^ READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)keys)[4*r]);   \
	\
	t4 = (uint8_t)(x1);      \
	T0(t4) \
	t5 = (uint8_t)((x2) >> 8); \
	T1(t5) \
	t5 = t5 ^ t4; \
	t6 = (uint8_t)((x3) >> 16);     \
	T2(t6) \
	t6 = t6 ^ t5; \
	t7 = (uint8_t)((x0) >> 24);     \
	T3(t7) \
	t7 = t7 ^ t6; \
	(y1) = t7 ^ READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)keys)[4 * r+1]);   \
	\
	t8 = (uint8_t)(x2);          \
	T0(t8) \
	t9 = (uint8_t)((x3) >> 8);     \
	T1(t9) \
	t9 = t9 ^ t8; \
	t10 = (uint8_t)((x0) >> 16);   \
	T2(t10) \
	t10 = t10 ^ t9; \
	t11 = (uint8_t)((x1) >> 24);   \
	T3(t11) \
	t11 = t11 ^ t10; \
	(y2) = t11 ^ READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)keys)[4 * r+2]); \
	\
	t12 = (uint8_t)(x3);         \
	T0(t12) \
	t13 = (uint8_t)((x0) >> 8);    \
	T1(t13) \
	t13 = t13 ^ t12; \
	t14 = (uint8_t)((x1) >> 16);   \
	T2(t14) \
	t14 = t14 ^ t13; \
	t15 = (uint8_t)((x2) >> 24);   \
	T3(t15) \
	t15 = t15 ^ t14; \
	(y3) = t15 ^ READ_ROUND_KEY_DOUBLE_WORD(((uint32_t*)keys)[4 * r+3]); \
}


#define aes128_enc_block(x, keys, output) \
{\
	uint32_t  w0, w1, w2, w3; \
	uint32_t  y0, y1, y2, y3; \
	uint32_t  z0, z1, z2, z3; \
	uint32_t  a0, a1, a2, a3; \
	uint32_t  b0, b1, b2, b3; \
	uint32_t  c0, c1, c2, c3; \
	uint32_t  d0, d1, d2, d3; \
	uint32_t  e0, e1, e2, e3; \
	uint32_t  f0, f1, f2, f3; \
	uint32_t  g0, g1, g2, g3; \
	\
	add_key(x, w0, w1, w2, w3, keys); \
	\
	round(w0, w1, w2, w3, y0, y1, y2, y3, keys, 1);\
	round(y0, y1, y2, y3, z0, z1, z2, z3, keys, 2); \
	round(z0, z1, z2, z3, a0, a1, a2, a3, keys, 3); \
	round(a0, a1, a2, a3, b0, b1, b2, b3, keys, 4); \
	round(b0, b1, b2, b3, c0, c1, c2, c3, keys, 5); \
	round(c0, c1, c2, c3, d0, d1, d2, d3, keys, 6); \
	round(d0, d1, d2, d3, e0, e1, e2, e3, keys, 7); \
	round(e0, e1, e2, e3, f0, f1, f2, f3, keys, 8); \
	round(f0, f1, f2, f3, g0, g1, g2, g3, keys, 9); \
	\
	last_round(g0, g1, g2, g3, (output), keys, 10); \
}


void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
	aes128_enc_block(block, roundKeys, block);
}

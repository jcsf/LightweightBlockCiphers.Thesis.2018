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
#include "tables.h"

/*
 *
 * Cipher Primitives
 *
 */
extern void ClefiaGfn4(uint32_t *block, uint32_t *rk, int8_t rounds_minus_1);
extern void ClefiaGfn4Inv(uint32_t *block, uint32_t* rk, int8_t rounds_minus_1);

#define round(block, rk, round) \
{ \
  ClefiaF0Xor((block), (rk)[0]) \
	ClefiaF1Xor((block) + 2, (rk)[1]) \
	(rk) += 2; \
  \
  /* Feistel Permutation */ \
  uint32_t temp = (block)[0]; \
  (block)[0] = (block)[1]; \
  (block)[1] = (block)[2]; \
  (block)[2] = (block)[3]; \
  (block)[3] = temp; \
}

#define last_round(block, rk) \
{ \
  ClefiaF0Xor((block), (rk)[0]) \
	ClefiaF1Xor((block) + 2, (rk)[1]) \
  (rk) += 2; \
}

#define ClefiaGfn4(block, rk) \
{ \
  round(block, rk, 1) \
  round(block, rk, 2) \
  round(block, rk, 3) \
  round(block, rk, 4) \
  round(block, rk, 5) \
  round(block, rk, 6) \
  round(block, rk, 7) \
  round(block, rk, 8) \
  round(block, rk, 9) \
  round(block, rk, 10) \
  round(block, rk, 11) \
  round(block, rk, 12) \
  round(block, rk, 13) \
  round(block, rk, 14) \
  round(block, rk, 15) \
  round(block, rk, 16) \
  round(block, rk, 17) \
  last_round(block, rk) \
}

#define ClefiaGfn4KeyScheduler(block, rk) \
{ \
  round(block, rk, 1) \
  round(block, rk, 2) \
  round(block, rk, 3) \
  round(block, rk, 4) \
  round(block, rk, 5) \
  round(block, rk, 6) \
  round(block, rk, 7) \
  round(block, rk, 8) \
  round(block, rk, 9) \
  round(block, rk, 10) \
  round(block, rk, 11) \
  last_round(block, rk) \
}

#define round_inv(block, rk, round) \
{ \
  ClefiaF0Xor((block), (rk)[0]) \
	ClefiaF1Xor((block) + 2, (rk)[1]) \
	(rk) -= 2; \
  \
  /* Feistel Permutation */ \
  uint32_t temp = (block)[3]; \
  (block)[3] = (block)[2]; \
  (block)[2] = (block)[1]; \
  (block)[1] = (block)[0]; \
  (block)[0] = temp; \
}

#define last_round_inv(block, rk) \
{ \
  ClefiaF0Xor((block), (rk)[0]) \
	ClefiaF1Xor((block) + 2, (rk)[1]) \
  (rk) -= 2; \
}

#define ClefiaGfn4Inv(block, rk) \
{ \
  round_inv(block, rk, 1) \
  round_inv(block, rk, 2) \
  round_inv(block, rk, 3) \
  round_inv(block, rk, 4) \
  round_inv(block, rk, 5) \
  round_inv(block, rk, 6) \
  round_inv(block, rk, 7) \
  round_inv(block, rk, 8) \
  round_inv(block, rk, 9) \
  round_inv(block, rk, 10) \
  round_inv(block, rk, 11) \
  round_inv(block, rk, 12) \
  round_inv(block, rk, 13) \
  round_inv(block, rk, 14) \
  round_inv(block, rk, 15) \
  round_inv(block, rk, 16) \
  round_inv(block, rk, 17) \
  last_round_inv(block, rk) \
}

#define ClefiaF0Xor(slice, rk) \
{ \
  uint32_t F0out, x1, x2, x3, x4; \
  \
  F0out = *(slice) ^ (rk); \
  \
  x1 = (uint8_t)(F0out); \
  x2 = (uint8_t)(F0out >> 8); \
  x3 = (uint8_t)(F0out >> 16); \
  x4 = (uint8_t)(F0out >> 24); \
  \
  T2_F0(x3) \
  T3_F0(x4) \
  \
  F0out = T0_F0[x1] ^ T1_F0[x2] ^ x3 ^ x4; \
  \
  (slice)[1] = (slice)[1] ^ F0out; \
}

#define ClefiaF1Xor(slice, rk) \
{ \
  uint32_t F1out, x1, x2, x3, x4; \
  \
  F1out = *(slice) ^ (rk); \
  \
  x1 = (uint8_t)(F1out); \
  x2 = (uint8_t)(F1out >> 8); \
  x3 = (uint8_t)(F1out >> 16); \
  x4 = (uint8_t)(F1out >> 24); \
  \
  T2_F1(x3) \
  T3_F1(x4) \
  \
  F1out = T0_F1[x1] ^ T1_F1[x2] ^ x3 ^ x4; \
  \
  (slice)[1] = (slice)[1] ^ F1out; \
}

#define ClefiaDoubleSwap(lk) \
{ \
  uint8_t t[16]; \
  \
  t[0]  = (lk[0] << 7) | (lk[1]  >> 1); \
  t[1]  = (lk[1] << 7) | (lk[2]  >> 1); \
  t[2]  = (lk[2] << 7) | (lk[3]  >> 1); \
  t[3]  = (lk[3] << 7) | (lk[4]  >> 1); \
  t[4]  = (lk[4] << 7) | (lk[5]  >> 1); \
  t[5]  = (lk[5] << 7) | (lk[6]  >> 1); \
  t[6]  = (lk[6] << 7) | (lk[7]  >> 1); \
  t[7]  = (lk[7] << 7) | (lk[15] & 0x7fU); \
  \
  t[8]  = (lk[8]  >> 7) | (lk[0]  & 0xfeU); \
  t[9]  = (lk[9]  >> 7) | (lk[8]  << 1); \
  t[10] = (lk[10] >> 7) | (lk[9]  << 1); \
  t[11] = (lk[11] >> 7) | (lk[10] << 1); \
  t[12] = (lk[12] >> 7) | (lk[11] << 1); \
  t[13] = (lk[13] >> 7) | (lk[12] << 1); \
  t[14] = (lk[14] >> 7) | (lk[13] << 1); \
  t[15] = (lk[15] >> 7) | (lk[14] << 1); \
  \
  memcpy(lk, t, 16); \
}

/*#define ClefiaDoubleSwapShouldBeCorrect(k) \
{ \
  uint32_t t[4]; \
  t[0] = (k[0] >> 7) | (k[1] << 25); \
  t[1] = (k[1] >> 7) | (k[3] & 0xfe000000U); \
  \
  t[2] = (k[2] << 7) | (k[0] & 0x7fU); \
  t[3] = (k[3] << 7) | (k[2] >> 25); \
  \
  k[0] = t[0]; \
  k[1] = t[1]; \
  k[2] = t[2]; \
  k[3] = t[3]; \
}*/

#endif /* PRIMITIVES_H */

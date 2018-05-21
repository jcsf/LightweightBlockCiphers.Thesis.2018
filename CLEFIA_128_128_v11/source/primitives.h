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

#define round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, round) \
{ \
  ClefiaF0Xor(x0, x1, rk[0], y0, y1, y2, y3, Fout) \
  ClefiaF1Xor(x2, x3, rk[1], y0, y1, y2, y3, Fout) \
  (rk) += 2; \
  \
  /* Feistel Permutation */ \
  temp = x0; \
  x0 = x1; \
  x1 = x2; \
  x2 = x3; \
  x3 = temp; \
}

#define last_round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk) \
{ \
  ClefiaF0Xor(x0, x1, rk[0], y0, y1, y2, y3, Fout) \
	ClefiaF1Xor(x2, x3, rk[1], y0, y1, y2, y3, Fout) \
  (rk) += 2; \
}

#define ClefiaGfn4(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk) \
{ \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 1) \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 2) \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 3) \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 4) \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 5) \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 6) \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 7) \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 8) \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 9) \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 10) \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 11) \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 12) \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 13) \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 14) \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 15) \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 16) \
  round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 17) \
  last_round(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk) \
}

#define round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, round) \
{ \
  ClefiaF0Xor(x0, x1, rk[0], y0, y1, y2, y3, Fout) \
  ClefiaF1Xor(x2, x3, rk[1], y0, y1, y2, y3, Fout) \
  (rk) -= 2; \
  \
  /* Feistel Permutation */ \
  temp = x3; \
  x3 = x2; \
  x2 = x1; \
  x1 = x0; \
  x0 = temp; \
}

#define last_round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk) \
{ \
  ClefiaF0Xor(x0, x1, rk[0], y0, y1, y2, y3, Fout) \
	ClefiaF1Xor(x2, x3, rk[1], y0, y1, y2, y3, Fout) \
  (rk) -= 2; \
}

#define ClefiaGfn4Inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk) \
{ \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 1) \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 2) \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 3) \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 4) \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 5) \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 6) \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 7) \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 8) \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 9) \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 10) \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 11) \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 12) \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 13) \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 14) \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 15) \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 16) \
  round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk, 17) \
  last_round_inv(x0, x1, x2, x3, y0, y1, y2, y3, Fout, rk) \
}

#define ClefiaF0Xor(slice, slice_1, rk, y0, y1, y2, y3, F0out) \
{ \
  F0out = slice ^ (rk); \
  \
  y0 = (uint8_t)(F0out); \
  y1 = (uint8_t)(F0out >> 8); \
  y2 = (uint8_t)(F0out >> 16); \
  y3 = (uint8_t)(F0out >> 24); \
  \
  T2_F0(y2) \
  T3_F0(y3) \
  \
  F0out = T0_F0[y0] ^ T1_F0[y1] ^ y2 ^ y3; \
  \
  slice_1 = slice_1 ^ F0out; \
}

#define ClefiaF1Xor(slice, slice_1, rk, y0, y1, y2, y3, F1out) \
{ \
  F1out = slice ^ (rk); \
  \
  y0 = (uint8_t)(F1out); \
  y1 = (uint8_t)(F1out >> 8); \
  y2 = (uint8_t)(F1out >> 16); \
  y3 = (uint8_t)(F1out >> 24); \
  \
  T2_F1(y2) \
  T3_F1(y3) \
  \
  F1out = T0_F1[y0] ^ T1_F1[y1] ^ y2 ^ y3; \
  \
  slice_1 = slice_1 ^ F1out; \
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
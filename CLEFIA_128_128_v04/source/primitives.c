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
#include <string.h>

#include "constants.h"
#include "primitives.h"

/*
 *
 * Cipher Primitives
 *
 */

uint8_t ClefiaMul2(uint8_t x)
{
  /* multiplication over GF(2^8) (p(x) = '11d') */
  if(x & 0x80U){
    x ^= 0x0eU;
  }
  return ((x << 1) | (x >> 7));
}

void ClefiaGfn4(uint32_t *block, uint32_t *rk, int8_t rounds_minus_1) {
  uint8_t i;
  uint32_t temp;

	for(i = rounds_minus_1; i > 0; i--) {
		ClefiaF0Xor(block, rk[0]);
		ClefiaF1Xor(block + 2, rk[1]);
		rk += 2;

		/* Feistel Permutation */
		temp = block[0];
		block[0] = block[1];
		block[1] = block[2];
		block[2] = block[3];
		block[3] = temp;
	}

  /* Last Round */
	ClefiaF0Xor(block, rk[0]);
	ClefiaF1Xor(block + 2, rk[1]);
}

void ClefiaGfn4Inv(uint32_t *block, uint32_t* rk, int8_t rounds_minus_1) {
  uint8_t i;
  uint32_t temp;

	for(i = rounds_minus_1; i > 0; i--) {
		ClefiaF0Xor(block, rk[0]);
		ClefiaF1Xor(block + 2, rk[1]);
		rk -= 2;

		/* Feistel Permutation */
		temp = block[3];
		block[3] = block[2];
		block[2] = block[1];
		block[1] = block[0];
		block[0] = temp;
	}

  /* Last Round */
	ClefiaF0Xor(block, rk[0]);
	ClefiaF1Xor(block + 2, rk[1]);
}

void ClefiaF0Xor(uint32_t *slice, const uint32_t rk)
{
  uint32_t F0out, y1, y2, y3, y4;
  uint8_t x1, x2, x3, x4;

  /* F0 */
  /* Key addition */
  F0out = *slice ^ rk;
  
  x1 = (uint8_t)(F0out);
  x2 = (uint8_t)(F0out >> 8);
  x3 = (uint8_t)(F0out >> 16);
  x4 = (uint8_t)(F0out >> 24);

  /*x1 = F0out & 0xFF;
  x2 = (F0out >> 8) & 0xFF;
  x3 = (F0out >> 16) & 0xFF;
  x4 = (F0out >> 24) & 0xFF;*/

  x1 = clefia_s0[x1];
  x2 = clefia_s1[x2];
  x3 = clefia_s0[x3];
  x4 = clefia_s1[x4];
  
  /* Diffusion layer (M0) */
  y1 =            x1  ^ ClefiaMul2(x2) ^ ClefiaMul4(x3) ^ ClefiaMul6(x4);
  y2 = ClefiaMul2(x1) ^            x2  ^ ClefiaMul6(x3) ^ ClefiaMul4(x4);
  y3 = ClefiaMul4(x1) ^ ClefiaMul6(x2) ^            x3  ^ ClefiaMul2(x4);
  y4 = ClefiaMul6(x1) ^ ClefiaMul4(x2) ^ ClefiaMul2(x3) ^            x4 ;
  
  F0out = y1 | (y2 << 8) | (y3 << 16) | (y4 << 24);

  slice[1] = slice[1] ^ F0out;
}

void ClefiaF1Xor(uint32_t *slice, const uint32_t rk)
{
  uint32_t F1out, y1, y2, y3, y4;
  uint8_t x1, x2, x3, x4;

  /* F1 */
  /* Key addition */
  F1out = *slice ^ rk;
 
  x1 = (uint8_t)(F1out);
  x2 = (uint8_t)(F1out >> 8);
  x3 = (uint8_t)(F1out >> 16);
  x4 = (uint8_t)(F1out >> 24);
  
  /*x1 = F0out & 0xFF;
  x2 = (F0out >> 8) & 0xFF;
  x3 = (F0out >> 16) & 0xFF;
  x4 = (F0out >> 24) & 0xFF;*/

  /* Substitution layer */
  x1 = clefia_s1[x1];
  x2 = clefia_s0[x2];
  x3 = clefia_s1[x3];
  x4 = clefia_s0[x4];
  /* Diffusion layer (M1) */
  y1 =            x1  ^ ClefiaMul8(x2) ^ ClefiaMul2(x3) ^ ClefiaMulA(x4);
  y2 = ClefiaMul8(x1) ^            x2  ^ ClefiaMulA(x3) ^ ClefiaMul2(x4);
  y3 = ClefiaMul2(x1) ^ ClefiaMulA(x2) ^            x3  ^ ClefiaMul8(x4);
  y4 = ClefiaMulA(x1) ^ ClefiaMul2(x2) ^ ClefiaMul8(x3) ^            x4 ;

  F1out = y1 | (y2 << 8) | (y3 << 16) | (y4 << 24);

  /* Xoring after F1 */
  slice[1] = slice[1] ^ F1out;
}

void ClefiaDoubleSwap(uint8_t *lk)
{
  uint8_t t[16];

  t[0]  = (lk[0] << 7) | (lk[1]  >> 1);
  t[1]  = (lk[1] << 7) | (lk[2]  >> 1);
  t[2]  = (lk[2] << 7) | (lk[3]  >> 1);
  t[3]  = (lk[3] << 7) | (lk[4]  >> 1);
  t[4]  = (lk[4] << 7) | (lk[5]  >> 1);
  t[5]  = (lk[5] << 7) | (lk[6]  >> 1);
  t[6]  = (lk[6] << 7) | (lk[7]  >> 1);
  t[7]  = (lk[7] << 7) | (lk[15] & 0x7fU);

  t[8]  = (lk[8]  >> 7) | (lk[0]  & 0xfeU);
  t[9]  = (lk[9]  >> 7) | (lk[8]  << 1);
  t[10] = (lk[10] >> 7) | (lk[9]  << 1);
  t[11] = (lk[11] >> 7) | (lk[10] << 1);
  t[12] = (lk[12] >> 7) | (lk[11] << 1);
  t[13] = (lk[13] >> 7) | (lk[12] << 1);
  t[14] = (lk[14] >> 7) | (lk[13] << 1);
  t[15] = (lk[15] >> 7) | (lk[14] << 1);

  memcpy(lk, t, 16);
}
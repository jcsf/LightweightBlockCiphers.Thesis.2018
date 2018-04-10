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
#include "tables.h"

/*
 *
 * Cipher Primitives
 *
 */

void inline ByteXor(uint8_t *dst, const uint8_t *a, const uint8_t *b, int8_t bytelen)
{
  while(bytelen-- > 0){
    *dst++ = *a++ ^ *b++;
  }
}

void ClefiaF0Xor(uint8_t *dst, const uint8_t *src, const uint8_t *rk)
{
  uint8_t x[4], y[4];

  /* F0 */
  /* Key addition */
  ByteXor(x, src, rk, 4);

  uint32_t fout = T0_F0[x[0]] ^ T1_F0[x[1]] ^ T2_F0[x[2]] ^ T3_F0[x[3]];

  y[0] = fout & 0xFF;
  y[1] = (fout >> 8) & 0xFF;
  y[2] = (fout >> 16) & 0xFF;
  y[3] = (fout >> 24) & 0xFF;

  /* Xoring after F0 */
  memcpy(dst + 0, src + 0, 4);
  ByteXor(dst + 4, src + 4, y, 4);
}

void ClefiaF1Xor(uint8_t *dst, const uint8_t *src, const uint8_t *rk)
{
  uint8_t x[4], y[4];

  /* F1 */
  /* Key addition */
  ByteXor(x, src, rk, 4);
 
  uint32_t fout = T0_F1[x[0]] ^ T1_F1[x[1]] ^ T2_F1[x[2]] ^ T3_F1[x[3]];

  y[0] = fout & 0xFF;
  y[1] = (fout >> 8) & 0xFF;
  y[2] = (fout >> 16) & 0xFF;
  y[3] = (fout >> 24) & 0xFF;

  /* Xoring after F1 */
  memcpy(dst + 0, src + 0, 4);
  ByteXor(dst + 4, src + 4, y, 4);
}

void ClefiaGfn4(uint8_t *block, const uint8_t *rk, int8_t r)
{
  uint8_t fin[16];

  memcpy(fin, block, 16);
  while(r-- > 0){
    ClefiaF0Xor(block + 0, fin + 0, rk + 0);
    ClefiaF1Xor(block + 8, fin + 8, rk + 4);
    rk += 8;
    
    if(r){ /* swapping for encryption */
      memcpy(fin + 0,  block + 4, 12);
      memcpy(fin + 12, block + 0, 4);
    }
  }
}

void ClefiaGfn4Inv(uint8_t *block, const uint8_t *rk, int8_t r)
{
  uint8_t fin[16];

  rk += (r - 1) * 8;
  memcpy(fin, block, 16);
  while(r-- > 0){
    ClefiaF0Xor(block + 0, fin + 0, rk + 0);
    ClefiaF1Xor(block + 8, fin + 8, rk + 4);
    rk -= 8;
    if(r){ /* swapping for decryption */
      memcpy(fin + 0,  block + 12, 4);
      memcpy(fin + 4, block + 0, 12);
    }
  }
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
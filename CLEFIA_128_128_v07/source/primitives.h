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

/*
 *
 * Cipher Primitives
 *
 */
extern void ClefiaF0Xor(uint32_t *slice, const uint32_t rk);
extern void ClefiaF1Xor(uint32_t *slice, const uint32_t rk);

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

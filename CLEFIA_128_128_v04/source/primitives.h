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

#define ClefiaMul4(_x) (ClefiaMul2(ClefiaMul2((_x))))
#define ClefiaMul6(_x) (ClefiaMul2((_x)) ^ ClefiaMul4((_x)))
#define ClefiaMul8(_x) (ClefiaMul2(ClefiaMul4((_x))))
#define ClefiaMulA(_x) (ClefiaMul2((_x)) ^ ClefiaMul8((_x)))

/*
 *
 * Cipher Primitives
 *
 */
extern uint8_t ClefiaMul2(uint8_t x);
extern void ClefiaGfn4(uint32_t *block, uint32_t* rk, int8_t rounds_minus_1);
extern void ClefiaGfn4Inv(uint32_t *block, uint32_t* rk, int8_t rounds_minus_1);
extern void ClefiaF0Xor(uint32_t *slice, const uint32_t rk);
extern void ClefiaF1Xor(uint32_t *slice, const uint32_t rk);
extern void ClefiaDoubleSwap(uint8_t *lk);

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

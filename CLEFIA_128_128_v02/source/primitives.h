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
extern void inline ByteXor(uint8_t *dst, const uint8_t *a, const uint8_t *b, int8_t bytelen);
extern uint8_t ClefiaMul2(uint8_t x);
extern void ClefiaF0Xor(uint8_t *dst, const uint8_t *src, const uint8_t *rk);
extern void ClefiaF1Xor(uint8_t *dst, const uint8_t *src, const uint8_t *rk);
extern void ClefiaGfn4(uint8_t *block, const uint8_t *rk, int8_t r);
extern void ClefiaGfn4Inv(uint8_t *block, const uint8_t *rk, int8_t r);
extern void ClefiaDoubleSwap(uint8_t *lk);

#endif /* PRIMITIVES_H */

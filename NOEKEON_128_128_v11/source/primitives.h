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
#include "constants.h"

/*
 *
 * Cipher primitives
 *
 */
#define ROTL(v, n) (((v) << n) | ((v) >> (32-n)))

#define THETA(w0, w1, w2, w3, k0, k1, k2, k3, temp0, temp1)\
{ \
    temp1  = w0 ^ w2; \
    temp0 = ROTL(temp1, 8) ^ temp1; \
    temp0 ^= ROTL(temp1, 24); \
    w1 ^= temp0; \
    w3 ^= temp0; \
    \
    w0 ^= k0; w1 ^= k1; w2 ^= k2; w3 ^= k3; \
    \
    temp1 = w1 ^ w3; \
    temp0 = ROTL(temp1, 8) ^ temp1; \
    temp0 ^= ROTL(temp1, 24); \
    w0 ^= temp0; \
    w2 ^= temp0; \
}

#define PI1(w0, w1, w2, w3)\
{ \
    w1 = ROTL(w1, 1); \
    w2 = ROTL(w2, 5); \
    w3 = ROTL(w3, 2); \
}

#define PI2(w0, w1, w2, w3)\
{\
    w1 = ROTL(w1, 31); \
    w2 = ROTL(w2, 27); \
    w3 = ROTL(w3, 30); \
}

#define GAMMA(w0, w1, w2, w3, temp0)\
{\
    w1 ^= ~w3 & ~w2; \
    w0 ^=  w2 &  w1; \
    \
    temp0 = w3; \
    w3 = w0; \
    w0 = temp0; \
    w2 ^= w0 ^ w1 ^ w3; \
    \
    w1 ^= ~w3 & ~w2; \
    w0 ^=  w2 &  w1; \
}

extern void CommonLoop(uint32_t* const block,  const uint32_t* const key, const uint8_t* const RC1, const uint8_t* const RC2);

#endif /* PRIMITIVES_H */

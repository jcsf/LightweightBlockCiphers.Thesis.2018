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

#define RCSHIFTREGFWD(rc)\
{ \
    if ((rc)&0x80) (rc)=((rc)<<1) ^ 0x1B; else (rc)<<=1; \
}

#define RCSHIFTREGBWD(rc)\
{ \
    if ((rc)&0x01) (rc)=((rc)>>1) ^ 0x8D; else (rc)>>=1; \
}

#define THETA(k, a)\
{ \
    uint32_t tmp, tmp2; \
    \
    tmp2  = a[0] ^ a[2]; \
    tmp = ROTL(tmp2, 8) ^ tmp2; \
    tmp ^= ROTL(tmp2, 24); \
    a[1] ^= tmp; \
    a[3] ^= tmp; \
    \
    a[0] ^= k[0]; a[1] ^= k[1]; a[2] ^= k[2]; a[3] ^= k[3]; \
    \
    tmp2 = a[1] ^ a[3]; \
    tmp = ROTL(tmp2, 8) ^ tmp2; \
    tmp ^= ROTL(tmp2, 24); \
    a[0] ^= tmp; \
    a[2] ^= tmp; \
}

#define PI1(a)\
{ \
  a[1] = ROTL(a[1], 1); \
  a[2] = ROTL(a[2], 5); \
  a[3] = ROTL(a[3], 2); \
}

#define PI2(a)\
{\
  a[1] = ROTL(a[1], 31); \
  a[2] = ROTL(a[2], 27); \
  a[3] = ROTL(a[3], 30); \
}

#define GAMMA(a)\
{\
    uint32_t tmp; \
    \
    a[1] ^= ~a[3] & ~a[2]; \
    a[0] ^=  a[2] & a[1]; \
    \
    tmp   = a[3]; \
    a[3]  = a[0]; \
    a[0]  = tmp; \
    a[2] ^= a[0] ^ a[1] ^ a[3]; \
    \
    a[1] ^= ~a[3] & ~a[2]; \
    a[0] ^=   a[2] & a[1]; \
}

/* Cipher Function Primitives */

#endif /* PRIMITIVES_H */

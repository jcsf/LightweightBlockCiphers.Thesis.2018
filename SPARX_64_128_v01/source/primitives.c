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

#include "constants.h"
#include "primitives.h"

/*
 *
 * Cipher constants
 *
 */

/* One keyless round of SPECK-32 */
void A(uint16_t * l, uint16_t * r)
{
    (*l) = ROTL((*l), 9);
    (*l) += (*r);
    (*r) = ROTL((*r), 2);
    (*r) ^= (*l);
}

/* One keyless inverse round of SPECK-32 */
void A_inv(uint16_t * l, uint16_t * r)
{
    (*r) ^= (*l);
    (*r) = ROTL((*r), 14);
    (*l) -= (*r);
    (*l) = ROTL((*l), 7);
}

/* The linear layers */
void L_2(uint16_t * x)
{
    uint16_t tmp = ROTL((x[0] ^ x[1]), 8);
    x[2] ^= x[0] ^ tmp;
    x[3] ^= x[1] ^ tmp;
    SWAP(x[0], x[2]);
    SWAP(x[1], x[3]);
}

void L_2_inv(uint16_t * x)
{
    uint16_t tmp;
    SWAP(x[0], x[2]);
    SWAP(x[1], x[3]);
    tmp = ROTL(x[0] ^ x[1], 8);
    x[2] ^= x[0] ^ tmp;
    x[3] ^= x[1] ^ tmp;
}

/* Key schedule  */
/* ============= */

/* The permutation of the key state */
void K_perm_64_128(uint16_t * k, uint16_t c)
{
    uint16_t tmp_0, tmp_1, i;
    /* Misty-like transformation */
    A(k+0, k+1);
    k[2] += k[0];
    k[3] += k[1];
    k[7] += c;
    /* Branch rotation */
    tmp_0 = k[6];
    tmp_1 = k[7];
    for (i=7 ; i>=2 ; i--)
    {
        k[i] = k[i-2];
    }
    k[0] = tmp_0;
    k[1] = tmp_1;
}
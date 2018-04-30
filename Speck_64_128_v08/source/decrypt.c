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

#include "cipher.h"
#include "constants.h"
#include "primitives.h"

#define round(leftSlice, rightSlice, rk, r)\
{ \
    *rightSlice = ror((*rightSlice ^ *leftSlice), BETA); \
    *leftSlice = rol(((*leftSlice ^ READ_ROUND_KEY_DOUBLE_WORD(rk[r])) - *rightSlice), ALPHA); \
}

void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
	uint32_t *rk = (uint32_t *)roundKeys;
    uint32_t *rightSlice = (uint32_t *)block;
    uint32_t *leftSlice = rightSlice + 1;

    round(leftSlice, rightSlice, rk, 26) // #1
    round(leftSlice, rightSlice, rk, 25) // #2
    round(leftSlice, rightSlice, rk, 24) // #3
    round(leftSlice, rightSlice, rk, 23) // #4
    round(leftSlice, rightSlice, rk, 22) // #5
    round(leftSlice, rightSlice, rk, 21) // #6
    round(leftSlice, rightSlice, rk, 20) // #7
    round(leftSlice, rightSlice, rk, 19) // #8
    round(leftSlice, rightSlice, rk, 18) // #9
    round(leftSlice, rightSlice, rk, 17) // #10
    round(leftSlice, rightSlice, rk, 16) // #11
    round(leftSlice, rightSlice, rk, 15) // #12
    round(leftSlice, rightSlice, rk, 14) // #13
    round(leftSlice, rightSlice, rk, 13) // #14
    round(leftSlice, rightSlice, rk, 12) // #15
    round(leftSlice, rightSlice, rk, 11) // #16
    round(leftSlice, rightSlice, rk, 10) // #17
    round(leftSlice, rightSlice, rk, 9) // #18
    round(leftSlice, rightSlice, rk, 8) // #19
    round(leftSlice, rightSlice, rk, 7) // #20
    round(leftSlice, rightSlice, rk, 6) // #21
    round(leftSlice, rightSlice, rk, 5) // #22
    round(leftSlice, rightSlice, rk, 4) // #23
    round(leftSlice, rightSlice, rk, 3) // #24
    round(leftSlice, rightSlice, rk, 2) // #25
    round(leftSlice, rightSlice, rk, 1) // #26
    round(leftSlice, rightSlice, rk, 0) // #27
}

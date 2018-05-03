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

#include "rot16.h"
#include "rot32.h"
#include "speckey.h"

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    register int8_t i, j;
    uint32_t *block32 = (uint32_t *)block;
    register uint32_t *roundKeys32 = (uint32_t *)roundKeys;

    register uint32_t left, right, temp;

    register uint16_t l, r;

    left = block32[0];
    right = block32[1];

    for (i = NUMBER_OF_ROUNDS; i > 0; i--)
    {
        /* Left Branch */
        for (j = 0; (j - 3) < 0 ; j++) {
            left ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys32[j]);
            speckey(left, l, r)
        }

        /* Right Branch */
        for (j = 3; (j - 6) < 0 ; j++) {
            right ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys32[j]);
            speckey(right, l, r)
        }

        /* linear layer */
        temp = left;
        left = right ^ (left ^ rot32l8(left) ^ rot32r8(left));
        right = temp;

        roundKeys32 += 6;
    }

    /* Post Whitening */
    block32[0] = left ^ READ_ROUND_KEY_DOUBLE_WORD(roundKeys32[0]);
    block32[1] = right ^ READ_ROUND_KEY_DOUBLE_WORD(roundKeys32[1]);
}

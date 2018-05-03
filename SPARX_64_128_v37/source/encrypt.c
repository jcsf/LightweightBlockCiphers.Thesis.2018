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

#include "rot32.h"
#include "speckey.h"

void Encrypt(uint8_t *block, uint8_t *roundKeys)
{
    uint8_t i;
    uint32_t *block32 = (uint32_t *)block;
    uint32_t *roundKeys32 = (uint32_t *)roundKeys;

    uint32_t left, right, temp;
    uint16_t *leftSlices = &left;
    uint16_t *rightSlices = &right;

    left = block32[0];
    right = block32[1];

    for (i = NUMBER_OF_ROUNDS; i > 0; i--)
    {
        /* left branch */
        left ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys32[0]);
        speckey(leftSlices, leftSlices + 1);

        left ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys32[1]);
        speckey(leftSlices, leftSlices + 1);

        left ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys32[2]);
        speckey(leftSlices, leftSlices + 1);

        /* right branch */
        right ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys32[3]);
        speckey(rightSlices, rightSlices + 1);

        right ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys32[4]);
        speckey(rightSlices, rightSlices + 1);

        right ^= READ_ROUND_KEY_DOUBLE_WORD(roundKeys32[5]);
        speckey(rightSlices, rightSlices + 1);

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

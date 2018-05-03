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

#include "speckey.h"

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
    uint8_t i;

    uint32_t *key32 = (uint32_t *)key;
    uint32_t *roundKeys32 = (uint32_t *)roundKeys;
    uint32_t *roundKeys32i = (uint32_t *)roundKeys;

    uint32_t temp, temp1;

    roundKeys32[0] = key32[0];
    roundKeys32[1] = key32[1];
    roundKeys32[2] = key32[2];
    temp = key32[3];

    roundKeys32 += 3;

    for(i = 1; i < 2 * NUMBER_OF_ROUNDS; i++)
    {
        roundKeys32[0] = temp + (i << 16);

        temp = roundKeys32i[0];
        temp = speckey((uint16_t) temp, (uint16_t) (temp >> 16));

        roundKeys32[1] = temp;

        temp1 = roundKeys32i[1];
        
        roundKeys32[2] = ((temp + temp1) & 0x0000FFFF) | ((temp & 0xFFFF0000) + (temp1 & 0xFFFF0000));

        temp = roundKeys32i[2];

        roundKeys32 += 3;
        roundKeys32i += 3;
    }

    roundKeys32[0] = temp + (TWO_TIMES_NUMBER_OF_ROUNDS << 16);

    temp = roundKeys32i[0];
    temp = speckey((uint16_t) temp, (uint16_t) (temp >> 16));

    roundKeys32[1] = temp;
}
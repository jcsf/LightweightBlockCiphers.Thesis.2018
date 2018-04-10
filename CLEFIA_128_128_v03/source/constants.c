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
#include <string.h>

#include "constants.h"
#include "primitives.h"

/*
 *
 * Cipher constants
 *
 */

void ClefiaConSet(uint8_t *con, const uint8_t *iv, int8_t lk)
{
  uint8_t t[2];
  uint8_t tmp;

  memcpy(t, iv, 2);
  
  while(lk-- > 0){
    con[0] = t[0] ^ 0xb7U; /* P_16 = 0xb7e1 (natural logarithm) */
    con[1] = t[1] ^ 0xe1U;
    con[2] = ~((t[0] << 1) | (t[1] >> 7));
    con[3] = ~((t[1] << 1) | (t[0] >> 7));
    con[4] = ~t[0] ^ 0x24U; /* Q_16 = 0x243f (circle ratio) */
    con[5] = ~t[1] ^ 0x3fU;
    con[6] = t[1];
    con[7] = t[0];
    con += 8;

    /* updating T */
    if(t[1] & 0x01U){
      t[0] ^= 0xa8U;
      t[1] ^= 0x30U;
    }
    tmp = t[0] << 7;
    t[0] = (t[0] >> 1) | (t[1] << 7);
    t[1] = (t[1] >> 1) | tmp;
  }    
}
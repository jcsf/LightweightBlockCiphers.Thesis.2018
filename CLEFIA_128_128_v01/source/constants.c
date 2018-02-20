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
/* Replace with the cipher constants definition */
/* S0 (8-bit S-box based on four 4-bit S-boxes) */
const uint8_t clefia_s0[256] = {
  0x57, 0x49, 0xd1, 0xc6, 0x2f, 0x33, 0x74, 0xfb,
  0x95, 0x6d, 0x82, 0xea, 0x0e, 0xb0, 0xa8, 0x1c,
  0x28, 0xd0, 0x4b, 0x92, 0x5c, 0xee, 0x85, 0xb1,
  0xc4, 0x0a, 0x76, 0x3d, 0x63, 0xf9, 0x17, 0xaf,
  0xbf, 0xa1, 0x19, 0x65, 0xf7, 0x7a, 0x32, 0x20,
  0x06, 0xce, 0xe4, 0x83, 0x9d, 0x5b, 0x4c, 0xd8,
  0x42, 0x5d, 0x2e, 0xe8, 0xd4, 0x9b, 0x0f, 0x13,
  0x3c, 0x89, 0x67, 0xc0, 0x71, 0xaa, 0xb6, 0xf5,
  0xa4, 0xbe, 0xfd, 0x8c, 0x12, 0x00, 0x97, 0xda,
  0x78, 0xe1, 0xcf, 0x6b, 0x39, 0x43, 0x55, 0x26,
  0x30, 0x98, 0xcc, 0xdd, 0xeb, 0x54, 0xb3, 0x8f,
  0x4e, 0x16, 0xfa, 0x22, 0xa5, 0x77, 0x09, 0x61,
  0xd6, 0x2a, 0x53, 0x37, 0x45, 0xc1, 0x6c, 0xae,
  0xef, 0x70, 0x08, 0x99, 0x8b, 0x1d, 0xf2, 0xb4,
  0xe9, 0xc7, 0x9f, 0x4a, 0x31, 0x25, 0xfe, 0x7c,
  0xd3, 0xa2, 0xbd, 0x56, 0x14, 0x88, 0x60, 0x0b,
  0xcd, 0xe2, 0x34, 0x50, 0x9e, 0xdc, 0x11, 0x05,
  0x2b, 0xb7, 0xa9, 0x48, 0xff, 0x66, 0x8a, 0x73,
  0x03, 0x75, 0x86, 0xf1, 0x6a, 0xa7, 0x40, 0xc2,
  0xb9, 0x2c, 0xdb, 0x1f, 0x58, 0x94, 0x3e, 0xed,
  0xfc, 0x1b, 0xa0, 0x04, 0xb8, 0x8d, 0xe6, 0x59,
  0x62, 0x93, 0x35, 0x7e, 0xca, 0x21, 0xdf, 0x47,
  0x15, 0xf3, 0xba, 0x7f, 0xa6, 0x69, 0xc8, 0x4d,
  0x87, 0x3b, 0x9c, 0x01, 0xe0, 0xde, 0x24, 0x52,
  0x7b, 0x0c, 0x68, 0x1e, 0x80, 0xb2, 0x5a, 0xe7,
  0xad, 0xd5, 0x23, 0xf4, 0x46, 0x3f, 0x91, 0xc9,
  0x6e, 0x84, 0x72, 0xbb, 0x0d, 0x18, 0xd9, 0x96,
  0xf0, 0x5f, 0x41, 0xac, 0x27, 0xc5, 0xe3, 0x3a,
  0x81, 0x6f, 0x07, 0xa3, 0x79, 0xf6, 0x2d, 0x38,
  0x1a, 0x44, 0x5e, 0xb5, 0xd2, 0xec, 0xcb, 0x90,
  0x9a, 0x36, 0xe5, 0x29, 0xc3, 0x4f, 0xab, 0x64,
  0x51, 0xf8, 0x10, 0xd7, 0xbc, 0x02, 0x7d, 0x8e
};

/* S1 (8-bit S-box based on inverse function) */
const uint8_t clefia_s1[256] = {
  0x6c, 0xda, 0xc3, 0xe9, 0x4e, 0x9d, 0x0a, 0x3d,
  0xb8, 0x36, 0xb4, 0x38, 0x13, 0x34, 0x0c, 0xd9,
  0xbf, 0x74, 0x94, 0x8f, 0xb7, 0x9c, 0xe5, 0xdc,
  0x9e, 0x07, 0x49, 0x4f, 0x98, 0x2c, 0xb0, 0x93,
  0x12, 0xeb, 0xcd, 0xb3, 0x92, 0xe7, 0x41, 0x60,
  0xe3, 0x21, 0x27, 0x3b, 0xe6, 0x19, 0xd2, 0x0e,
  0x91, 0x11, 0xc7, 0x3f, 0x2a, 0x8e, 0xa1, 0xbc,
  0x2b, 0xc8, 0xc5, 0x0f, 0x5b, 0xf3, 0x87, 0x8b,
  0xfb, 0xf5, 0xde, 0x20, 0xc6, 0xa7, 0x84, 0xce,
  0xd8, 0x65, 0x51, 0xc9, 0xa4, 0xef, 0x43, 0x53,
  0x25, 0x5d, 0x9b, 0x31, 0xe8, 0x3e, 0x0d, 0xd7,
  0x80, 0xff, 0x69, 0x8a, 0xba, 0x0b, 0x73, 0x5c,
  0x6e, 0x54, 0x15, 0x62, 0xf6, 0x35, 0x30, 0x52,
  0xa3, 0x16, 0xd3, 0x28, 0x32, 0xfa, 0xaa, 0x5e,
  0xcf, 0xea, 0xed, 0x78, 0x33, 0x58, 0x09, 0x7b,
  0x63, 0xc0, 0xc1, 0x46, 0x1e, 0xdf, 0xa9, 0x99,
  0x55, 0x04, 0xc4, 0x86, 0x39, 0x77, 0x82, 0xec,
  0x40, 0x18, 0x90, 0x97, 0x59, 0xdd, 0x83, 0x1f,
  0x9a, 0x37, 0x06, 0x24, 0x64, 0x7c, 0xa5, 0x56,
  0x48, 0x08, 0x85, 0xd0, 0x61, 0x26, 0xca, 0x6f,
  0x7e, 0x6a, 0xb6, 0x71, 0xa0, 0x70, 0x05, 0xd1,
  0x45, 0x8c, 0x23, 0x1c, 0xf0, 0xee, 0x89, 0xad,
  0x7a, 0x4b, 0xc2, 0x2f, 0xdb, 0x5a, 0x4d, 0x76,
  0x67, 0x17, 0x2d, 0xf4, 0xcb, 0xb1, 0x4a, 0xa8,
  0xb5, 0x22, 0x47, 0x3a, 0xd5, 0x10, 0x4c, 0x72,
  0xcc, 0x00, 0xf9, 0xe0, 0xfd, 0xe2, 0xfe, 0xae,
  0xf8, 0x5f, 0xab, 0xf1, 0x1b, 0x42, 0x81, 0xd6,
  0xbe, 0x44, 0x29, 0xa6, 0x57, 0xb9, 0xaf, 0xf2,
  0xd4, 0x75, 0x66, 0xbb, 0x68, 0x9f, 0x50, 0x02,
  0x01, 0x3c, 0x7f, 0x8d, 0x1a, 0x88, 0xbd, 0xac,
  0xf7, 0xe4, 0x79, 0x96, 0xa2, 0xfc, 0x6d, 0xb2,
  0x6b, 0x03, 0xe1, 0x2e, 0x7d, 0x14, 0x95, 0x1d
};

void ClefiaConSet(uint8_t *con, const uint8_t *iv, int8_t lk)
{
  uint8_t t[2];
  uint8_t tmp;

  ByteCpy(t, iv, 2);
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
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

#include "test_vectors.h"

/*
 *
 * Test vectors
 *
 */
/* Replace with the cipher test vectors */
const uint8_t expectedPlaintext[BLOCK_SIZE] = {
    0x20, 0x6d, 0x61, 0x64,
    0x65, 0x20, 0x69, 0x74,
    0x20, 0x65, 0x71, 0x75,
    0x69, 0x76, 0x61, 0x6c
};

const uint8_t expectedKey[KEY_SIZE] = {
    0x0, 0x1, 0x2, 0x3,
    0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xa, 0xb,
    0xc, 0xd, 0xe, 0xf
};

const uint8_t expectedCiphertext[BLOCK_SIZE] = {
    0x18, 0x0d, 0x57, 0x5c,
    0xdf, 0xfe, 0x60, 0x78,
    0x65, 0x32, 0x78, 0x79,
    0x51, 0x98, 0x5d, 0xa6
};
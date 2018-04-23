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
/* Little Endian Test Vectors */
const uint8_t expectedPlaintext[BLOCK_SIZE] = {0x1b, 0x42, 0x78, 0x2a, 0x92, 0xd0, 0xc7, 0x87, 0x3f, 0x11, 0x26, 0x4f, 0xb2, 0x49, 0x13, 0x1d};
const uint8_t expectedKey[KEY_SIZE] = {0x51, 0x68, 0x65, 0xb1, 0xfa, 0x29, 0x9e, 0x69, 0x48, 0x01, 0xb7, 0x24, 0xfc, 0x2d, 0x3d, 0x50};
const uint8_t expectedCiphertext[BLOCK_SIZE] = {0xe0, 0x87, 0xf6, 0xe2, 0xf, 0x66, 0x75, 0x7b, 0x33, 0x22, 0x37, 0xfc, 0x2c, 0x53, 0x47, 0xbc};
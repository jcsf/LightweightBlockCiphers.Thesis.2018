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
const uint8_t expectedPlaintext[BLOCK_SIZE] = {0x2a, 0x78, 0x42, 0x1b, 0x87, 0xc7, 0xd0, 0x92, 0x4f, 0x26, 0x11, 0x3f, 0x1d, 0x13, 0x49, 0xb2};
const uint8_t expectedKey[KEY_SIZE] = {0xb1, 0x65, 0x68, 0x51, 0x69, 0x9e, 0x29, 0xfa, 0x24, 0xb7, 0x01, 0x48, 0x50, 0x3d, 0x2d, 0xfc};
const uint8_t expectedCiphertext[BLOCK_SIZE] = {0xe2, 0xf6, 0x87, 0xe0, 0x7b, 0x75, 0x66, 0x0f, 0xfc, 0x37, 0x22, 0x33, 0xbc, 0x47, 0x53, 0x2c};

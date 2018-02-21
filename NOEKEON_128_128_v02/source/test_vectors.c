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
const uint8_t expectedPlaintext[BLOCK_SIZE] = {0x52, 0xf8, 0x8a, 0x7b, 0x28, 0x3c, 0x1f, 0x7b, 0xdf, 0x7b, 0x6f, 0xaa, 0x50, 0x11, 0xc7, 0xd8};
const uint8_t expectedKey[KEY_SIZE] = {0xba, 0x69, 0x33, 0x81, 0x92, 0x99, 0xc7, 0x16, 0x99, 0xa9, 0x9f, 0x08, 0xf6, 0x78, 0x17, 0x8b};
const uint8_t expectedCiphertext[BLOCK_SIZE] = {0x50, 0x96, 0xf2, 0xbf, 0xc8, 0x2a, 0xe6, 0xe2, 0xd9, 0x49, 0x55, 0x15, 0xc2, 0x77, 0xfa, 0x70};

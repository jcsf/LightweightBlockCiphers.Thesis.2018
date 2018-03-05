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
const uint8_t expectedPlaintext[BLOCK_SIZE] = {0x7b, 0x8a, 0xf8, 0x52, 0x7b, 0x1f, 0x3c, 0x28, 0xaa, 0x6f, 0x7b, 0xdf, 0xd8, 0xc7, 0x11, 0x50};
const uint8_t expectedKey[KEY_SIZE] = {0x81, 0x33, 0x69, 0xba, 0x16, 0xc7, 0x99, 0x92, 0x8, 0x9f, 0xa9, 0x99, 0x8b, 0x17, 0x78, 0xf6};
const uint8_t expectedCiphertext[BLOCK_SIZE] = {0xbf, 0xf2, 0x96, 0x50, 0xe2, 0xe6, 0x2a, 0xc8, 0x15, 0x55, 0x49, 0xd9, 0x70, 0xfa, 0x77, 0xc2};

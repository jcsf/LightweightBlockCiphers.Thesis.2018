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

const uint8_t expectedPlaintext[BLOCK_SIZE] = {0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
const uint8_t expectedKey[KEY_SIZE] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF, 0x01,0x23};
const uint8_t expectedCiphertext[BLOCK_SIZE] = {0x32,0x8C,0x79,0x8A,0x0E,0xB2,0x5A,0x3B};
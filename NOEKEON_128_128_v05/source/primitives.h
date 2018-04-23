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

#ifndef PRIMITIVES_H
#define PRIMITIVES_H

#include "data_types.h"
#include "constants.h"

/*
 *
 * Cipher primitives
 *
 */
#define ROTL(v, n) (((v) << n) | ((v) >> (32-n)))

/* Cipher Function Primitives */
extern void Theta (uint32_t const * const k, uint32_t * const a);
extern void Pi1(uint32_t * const a);
extern void Pi2(uint32_t * const a);
extern void Gamma(uint32_t * const a);
extern void Round (uint32_t const * const k, uint32_t * const a, uint8_t const RC1, uint8_t const RC2);

#endif /* PRIMITIVES_H */

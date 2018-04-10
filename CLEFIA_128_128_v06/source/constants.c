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

/* Constants 128-bits key*/
uint32_t con128[60] = {
  0xeb7a6bf5, 0x428a4a99, 0x75bda496, 0x214585fa, 0x8a765b73, 0xc4ba7a1f, 0x453bbcd5, 0x625d9db9, 
  0x9235d752, 0xe536f63e, 0xc91a7ac5, 0x729b5ba9, 0x5425b45a, 0xed559536, 0x9aba5315, 0xa2b27279, 
  0x4d5db8e6, 0x5159998a, 0x9606554b, 0xfcb47427, 0x4b03bbc9, 0x7e5a9aa5, 0xa581cc88, 0x3f2dede4, 
  0xe2686f7c, 0xcb8e4e10, 0x713426d2, 0x65c707be, 0x8321a51, 0xe6fb3b3d, 0x34b18410, 0xa765a57c, 
  0xaaf04b30, 0x87aa6a5c, 0x557834f4, 0x43d51598, 0x1a141342, 0xf5f2322e, 0xd0a18cd, 0x7af939a1, 
  0x362d855e, 0xe964a432, 0x9b1653c3, 0x74b272af, 0x4d8bb88d, 0x3a5999e1, 0x966dd57e, 0xc934f412, 
  0xcb367bd3, 0x649a5abf, 0x659bac85, 0x324d8de9, 0x8265df7a, 0xcd3efe16, 0xc1327ed1, 0x669f5fbd, 
  0x5031b650, 0xe757973c, 0x98b05210, 0xa7b3737c
};
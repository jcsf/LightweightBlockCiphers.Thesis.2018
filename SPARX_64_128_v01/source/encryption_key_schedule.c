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

#include "cipher.h"
#include "constants.h"
#include "primitives.h"

/* Takes a 128 bit master key and turns it into 2*(N_STEPS+1) subkeys of 96 bits 
void key_schedule(uint16_t subkeys[][2*ROUNDS_PER_STEPS], uint16_t * master_key)*/

void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys)
{
	uint16_t master_key[KEY_SIZE/2];
    uint16_t *temp = (uint16_t*) key;
    /*uint16_t subkeys[][2*ROUNDS_PER_STEPS] = (uint16_t[][]) roundKeys;*/
    uint16_t* subkeys = (uint16_t*) roundKeys;

	uint8_t c, i;
    for(i = 0; i < KEY_SIZE/2; i++) {
        master_key[i] = temp[i];
    }
    
    for (c=0 ; c<(N_BRANCHES*N_STEPS+1) ; c++)
    {
        for (i=0 ; i<2*ROUNDS_PER_STEPS ; i++)
        {
            /*subkeys[c][i] = master_key[i];*/
            subkeys[MATRIX_TO_ARRAY(c, i)] = master_key[i];
        }
        K_perm(master_key, c+1);
    }
}
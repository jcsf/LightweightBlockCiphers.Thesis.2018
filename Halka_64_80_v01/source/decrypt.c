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

#include "cipher.h"
#include "constants.h"


void Decrypt(uint8_t *block, uint8_t *roundKeys)
{
    uint8_t tempds[BLOCK_SIZE];
    int8_t i, j;

    for (j=0;j < BLOCK_SIZE;j++)
    {
        block[j]=block[j]^roundKeys[MATRIX_TO_ARRAY(24, j)];
    }

    for (i = NUMBER_OF_ROUNDS - 1;i > -1; i--)
	{
		//Permutation
		memset(tempds, 0, BLOCK_SIZE);
		
        PERMUTATION_INV_XY_IJ(0, 0, 1, 2);
        PERMUTATION_INV_XY_IJ(0, 1, 2, 5);
        PERMUTATION_INV_XY_IJ(0, 2, 3, 4);
        PERMUTATION_INV_XY_IJ(0, 3, 4, 6);
        PERMUTATION_INV_XY_IJ(0, 4, 5, 4);
        PERMUTATION_INV_XY_IJ(0, 5, 6, 0);
        PERMUTATION_INV_XY_IJ(0, 6, 7, 3);
        PERMUTATION_INV_XY_IJ(0, 7, 0, 1);

        PERMUTATION_INV_XY_IJ(1, 0, 6, 3);
        PERMUTATION_INV_XY_IJ(1, 1, 1, 7);
        PERMUTATION_INV_XY_IJ(1, 2, 5, 1);
        PERMUTATION_INV_XY_IJ(1, 3, 0, 2);
        PERMUTATION_INV_XY_IJ(1, 4, 7, 4);
        PERMUTATION_INV_XY_IJ(1, 5, 4, 2);
        PERMUTATION_INV_XY_IJ(1, 6, 3, 0);
        PERMUTATION_INV_XY_IJ(1, 7, 2, 4);

        PERMUTATION_INV_XY_IJ(2, 0, 7, 0);
        PERMUTATION_INV_XY_IJ(2, 1, 0, 6);
        PERMUTATION_INV_XY_IJ(2, 2, 2, 1);
        PERMUTATION_INV_XY_IJ(2, 3, 3, 7);
        PERMUTATION_INV_XY_IJ(2, 4, 4, 4);
        PERMUTATION_INV_XY_IJ(2, 5, 6, 5);
        PERMUTATION_INV_XY_IJ(2, 6, 1, 4);
        PERMUTATION_INV_XY_IJ(2, 7, 5, 6);

        PERMUTATION_INV_XY_IJ(3, 0, 3, 6);
        PERMUTATION_INV_XY_IJ(3, 1, 6, 4);
        PERMUTATION_INV_XY_IJ(3, 2, 1, 3);
        PERMUTATION_INV_XY_IJ(3, 3, 0, 4);
        PERMUTATION_INV_XY_IJ(3, 4, 2, 7);
        PERMUTATION_INV_XY_IJ(3, 5, 4, 3);
        PERMUTATION_INV_XY_IJ(3, 6, 5, 0);
        PERMUTATION_INV_XY_IJ(3, 7, 7, 7);

        PERMUTATION_INV_XY_IJ(4, 0, 1, 0);
        PERMUTATION_INV_XY_IJ(4, 1, 4, 7);
        PERMUTATION_INV_XY_IJ(4, 2, 0, 3);
        PERMUTATION_INV_XY_IJ(4, 3, 5, 3);
        PERMUTATION_INV_XY_IJ(4, 4, 7, 1);
        PERMUTATION_INV_XY_IJ(4, 5, 6, 1);
        PERMUTATION_INV_XY_IJ(4, 6, 2, 0);
        PERMUTATION_INV_XY_IJ(4, 7, 3, 1);

        PERMUTATION_INV_XY_IJ(5, 0, 4, 5);
        PERMUTATION_INV_XY_IJ(5, 1, 5, 2);
        PERMUTATION_INV_XY_IJ(5, 2, 7, 5);
        PERMUTATION_INV_XY_IJ(5, 3, 6, 2);
        PERMUTATION_INV_XY_IJ(5, 4, 0, 0);
        PERMUTATION_INV_XY_IJ(5, 5, 1, 1);
        PERMUTATION_INV_XY_IJ(5, 6, 2, 2);
        PERMUTATION_INV_XY_IJ(5, 7, 3, 2);

        PERMUTATION_INV_XY_IJ(6, 0, 7, 2);
        PERMUTATION_INV_XY_IJ(6, 1, 6, 7);
        PERMUTATION_INV_XY_IJ(6, 2, 0, 7);
        PERMUTATION_INV_XY_IJ(6, 3, 2, 3);
        PERMUTATION_INV_XY_IJ(6, 4, 3, 5);
        PERMUTATION_INV_XY_IJ(6, 5, 1, 6);
        PERMUTATION_INV_XY_IJ(6, 6, 5, 7);
        PERMUTATION_INV_XY_IJ(6, 7, 4, 0);

        PERMUTATION_INV_XY_IJ(7, 0, 4, 1);
        PERMUTATION_INV_XY_IJ(7, 1, 0, 5);
        PERMUTATION_INV_XY_IJ(7, 2, 7, 6);
        PERMUTATION_INV_XY_IJ(7, 3, 5, 5);
        PERMUTATION_INV_XY_IJ(7, 4, 1, 5);
        PERMUTATION_INV_XY_IJ(7, 5, 6, 6);
        PERMUTATION_INV_XY_IJ(7, 6, 2, 6);
        PERMUTATION_INV_XY_IJ(7, 7, 3, 3);
        
        /*
		tempds[5]=tempds[5]^(((block[0]>>0)&1)<<4); // 0 - 44
        tempds[0]=tempds[0]^(((block[0]>>1)&1)<<7); // 1 - 7
		tempds[1]=tempds[1]^(((block[0]>>2)&1)<<3); // 2 - 11
		tempds[4]=tempds[4]^(((block[0]>>3)&1)<<2); // 3 - 34
		tempds[3]=tempds[3]^(((block[0]>>4)&1)<<3); // 4 - 27
		tempds[7]=tempds[7]^(((block[0]>>5)&1)<<1); // 5 - 57
		tempds[2]=tempds[2]^(((block[0]>>6)&1)<<1); // 6 - 17
		tempds[6]=tempds[6]^(((block[0]>>7)&1)<<2); // 7 - 50
		tempds[4]=tempds[4]^(((block[1]>>0)&1)<<0); // 8 - 32
		tempds[5]=tempds[5]^(((block[1]>>1)&1)<<5); // 9 - 45
		tempds[0]=tempds[0]^(((block[1]>>2)&1)<<0); // 10 - 0
		tempds[3]=tempds[3]^(((block[1]>>3)&1)<<2); // 11 - 26
		tempds[2]=tempds[2]^(((block[1]>>4)&1)<<6); // 12 - 22
		tempds[7]=tempds[7]^(((block[1]>>5)&1)<<4); // 13 - 60
		tempds[6]=tempds[6]^(((block[1]>>6)&1)<<5); // 14 - 53
		tempds[1]=tempds[1]^(((block[1]>>7)&1)<<1); // 15 - 9
		tempds[4]=tempds[4]^(((block[2]>>0)&1)<<6); // 16 - 38
		tempds[2]=tempds[2]^(((block[2]>>1)&1)<<2); // 17 - 18
		tempds[5]=tempds[5]^(((block[2]>>2)&1)<<6); // 18 - 46
		tempds[6]=tempds[6]^(((block[2]>>3)&1)<<3); // 19 - 51
		tempds[1]=tempds[1]^(((block[2]>>4)&1)<<7); // 20 - 15
		tempds[0]=tempds[0]^(((block[2]>>5)&1)<<1); // 21 - 1
		tempds[7]=tempds[7]^(((block[2]>>6)&1)<<6); // 22 - 62
		tempds[3]=tempds[3]^(((block[2]>>7)&1)<<4); // 23 - 28
		tempds[1]=tempds[1]^(((block[3]>>0)&1)<<6); // 24 - 14
		tempds[4]=tempds[4]^(((block[3]>>1)&1)<<7); // 25 - 39
		tempds[5]=tempds[5]^(((block[3]>>2)&1)<<7); // 26 - 47
		tempds[7]=tempds[7]^(((block[3]>>3)&1)<<7); // 27 - 63
		tempds[0]=tempds[0]^(((block[3]>>4)&1)<<2); // 28 - 2
		tempds[6]=tempds[6]^(((block[3]>>5)&1)<<4); // 29 - 52
		tempds[3]=tempds[3]^(((block[3]>>6)&1)<<0); // 30 - 24
		tempds[2]=tempds[2]^(((block[3]>>7)&1)<<3); // 31 - 19
		tempds[6]=tempds[6]^(((block[4]>>0)&1)<<7); // 32 - 55
		tempds[7]=tempds[7]^(((block[4]>>1)&1)<<0); // 33 - 56
		tempds[1]=tempds[1]^(((block[4]>>2)&1)<<5); // 34 - 13
		tempds[3]=tempds[3]^(((block[4]>>3)&1)<<5); // 35 - 29
		tempds[2]=tempds[2]^(((block[4]>>4)&1)<<4); // 36 - 20
		tempds[5]=tempds[5]^(((block[4]>>5)&1)<<0); // 37 - 40
		tempds[0]=tempds[0]^(((block[4]>>6)&1)<<3); // 38 - 3
		tempds[4]=tempds[4]^(((block[4]>>7)&1)<<1); // 39 - 33

		tempds[3]=tempds[3]^(((block[5]>>0)&1)<<6); // 40 - 30
		tempds[1]=tempds[1]^(((block[5]>>1)&1)<<2); // 41 - 10
		tempds[5]=tempds[5]^(((block[5]>>2)&1)<<1); // 42 - 41
		tempds[4]=tempds[4]^(((block[5]>>3)&1)<<3); // 43 - 35
		tempds[0]=tempds[0]^(((block[5]>>4)&1)<<4); // 44 - 4
		tempds[7]=tempds[7]^(((block[5]>>5)&1)<<3); // 45 - 59
		tempds[2]=tempds[2]^(((block[5]>>6)&1)<<7); // 46 - 23
		tempds[6]=tempds[6]^(((block[5]>>7)&1)<<6); // 47 - 54
		tempds[0]=tempds[0]^(((block[6]>>0)&1)<<5); // 48 - 5
		tempds[4]=tempds[4]^(((block[6]>>1)&1)<<5); // 49 - 37
		tempds[5]=tempds[5]^(((block[6]>>2)&1)<<3); // 50 - 43
		tempds[1]=tempds[1]^(((block[6]>>3)&1)<<0); // 51 - 8
		tempds[3]=tempds[3]^(((block[6]>>4)&1)<<1); // 52 - 25
		tempds[2]=tempds[2]^(((block[6]>>5)&1)<<5); // 53 - 21
		tempds[7]=tempds[7]^(((block[6]>>6)&1)<<5); // 54 - 61
		tempds[6]=tempds[6]^(((block[6]>>7)&1)<<1); // 55 - 49
		tempds[2]=tempds[2]^(((block[7]>>0)&1)<<0); // 56 - 16
		tempds[4]=tempds[4]^(((block[7]>>1)&1)<<4); // 57 - 36
		tempds[6]=tempds[6]^(((block[7]>>2)&1)<<0); // 58 - 48
		tempds[0]=tempds[0]^(((block[7]>>3)&1)<<6); // 59 - 6
		tempds[1]=tempds[1]^(((block[7]>>4)&1)<<4); // 60 - 12 
		tempds[5]=tempds[5]^(((block[7]>>5)&1)<<2); // 61 - 42
		tempds[7]=tempds[7]^(((block[7]>>6)&1)<<2); // 62 - 58
		tempds[3]=tempds[3]^(((block[7]>>7)&1)<<7); // 63 - 31
		*/

		memcpy(block, tempds, BLOCK_SIZE);
        
		for(j=0;j < BLOCK_SIZE;j++)
		{
			//S-Box-Inv Transformation
			block[j]=S_BOX_INV[(block[j])];

			//Add Round Key
			block[j] = block[j] ^ roundKeys[MATRIX_TO_ARRAY(i, j)];
		}
	}
}

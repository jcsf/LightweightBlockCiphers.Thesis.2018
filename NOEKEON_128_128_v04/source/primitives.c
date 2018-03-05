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

#include "constants.h"
#include "primitives.h"

/*
 *
 * Cipher primitives
 *
 */

/*==================================================================================*/
void Theta (uint32_t const * const k, uint32_t * const a)
/*----------------------------------------------------------------------------------*/
/* DIFFUSION - Linear step THETA, involution
/*==================================================================================*/
{
  uint32_t tmp;

  tmp  = a[0]^a[2]; 
  tmp ^= ROTL32(tmp,8)^ROTL32(tmp,24); 
  a[1]^= tmp; 
  a[3]^= tmp; 

  a[0] ^= k[0]; a[1] ^= k[1]; a[2] ^= k[2]; a[3] ^= k[3]; 

  tmp  = a[1]^a[3]; 
  tmp ^= ROTL32(tmp,8)^ROTL32(tmp,24); 
  a[0]^= tmp; 
  a[2]^= tmp; 

} /* Theta */


/*==================================================================================*/
void Pi1(uint32_t * const a)
/*----------------------------------------------------------------------------------*/
/* DISPERSION - Rotations Pi1
/*==================================================================================*/
{ a[1] = ROTL32 (a[1], 1); 
  a[2] = ROTL32 (a[2], 5); 
  a[3] = ROTL32 (a[3], 2); 
}  /* Pi1 */


/*==================================================================================*/
void Pi2(uint32_t * const a)
/*----------------------------------------------------------------------------------*/
/* DISPERSION - Rotations Pi2
/*==================================================================================*/
{ a[1] = ROTL32 (a[1], 31);
  a[2] = ROTL32 (a[2], 27); 
  a[3] = ROTL32 (a[3], 30); 
}  /* Pi2 */


/*==================================================================================*/
void Gamma(uint32_t * const a)
/*----------------------------------------------------------------------------------*/
/* NONLINEAR - gamma, involution
/*----------------------------------------------------------------------------------*/
/* Input of i_th s-box = (i3)(i2)(i1)(i0), with (i3) = i_th bit of a[3]
 *                                              (i2) = i_th bit of a[2]
 *                                              (i1) = i_th bit of a[1]
 *                                              (i0) = i_th bit of a[0]
 *
 * gamma = NLIN o LIN o NLIN : (i3)(i2)(i1)(i0) --> (o3)(o2)(o1)(o0)
 *
 * NLIN ((i3) = (o3) = (i3)                     NLIN is an involution
 *       (i2)   (o2)   (i2)                      i.e. evaluation order of i1 & i0
 *       (i1)   (o1)   (i1+(~i3.~i2))                 can be swapped
 *       (i0))  (o0)   (i0+(i2.i1))
 * 
 *  LIN ((i3) = (o3) = (0.i3+0.i2+0.i1+  i0)    LIN is an involution
 *       (i2)   (o2)   (  i3+  i2+  i1+  i0)    
 *       (i1)   (o1)   (0.i3+0.i2+  i1+0.i0)    
 *       (i0))  (o0)   (  i3+0.i2+0.i1+0.i0)    
 *
/*==================================================================================*/
{ uint32_t tmp;

  /* first non-linear step in gamma */
  a[1] ^= ~a[3] & ~a[2];
  a[0] ^=   a[2] & a[1];

  /* linear step in gamma */
  tmp   = a[3];
  a[3]  = a[0];
  a[0]  = tmp;
  a[2] ^= a[0]^a[1]^a[3];

  /* last non-linear step in gamma */
  a[1] ^= ~a[3] & ~a[2];
  a[0] ^=   a[2] & a[1];
} /* Gamma */


/*==================================================================================*/
void Round (uint32_t const * const k, uint32_t * const a, uint8_t const RC1, uint8_t const RC2)
/*----------------------------------------------------------------------------------*/
/* The round function, common to both encryption and decryption
/* - Round constants is added to the rightmost byte of the leftmost 32-bit word (=a0)
/*==================================================================================*/
{ 
  a[0] ^= RC1;
  Theta(k,a); 
  a[0] ^= RC2;
  Pi1(a); 
  Gamma(a); 
  Pi2(a); 
}  /* Round */

/*==================================================================================*/
void RCShiftRegFwd (uint8_t * const RC)
/*----------------------------------------------------------------------------------*/
/* The shift register that computes round constants - Forward Shift
/*==================================================================================*/
{ 

  if ((*RC)&0x80) (*RC)=((*RC)<<1) ^ 0x1B; else (*RC)<<=1;
  
} /* RCShiftRegFwd */

/*==================================================================================*/
void RCShiftRegBwd (uint8_t * const RC)
/*----------------------------------------------------------------------------------*/
/* The shift register that computes round constants - Backward Shift
/*==================================================================================*/
{ 

  if ((*RC)&0x01) (*RC)=((*RC)>>1) ^ 0x8D; else (*RC)>>=1;
  
} /* RCShiftRegBwd */

/*==================================================================================*/
void CommonLoop (uint32_t const * const k, uint32_t * const a, uint8_t RC1, uint8_t RC2)
/*----------------------------------------------------------------------------------*/
/* loop - several round functions, ended by theta
/*==================================================================================*/
{ 
  uint8_t i;

  for(i=0 ; i<NUMBER_OF_ROUNDS ; i++) {
    Round(k,a,RC1,RC2); 
    RCShiftRegFwd(&RC1);
    RCShiftRegBwd(&RC2);
  }
  a[0]^=RC1;
  Theta(k,a); 
  a[0]^=RC2;

}
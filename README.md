# LightweightBlockCiphers.Thesis.2018
Block Ciphers implemented for the Master Thesis@IST
(2017/2018)

João Fernandes, 87786, jcsf_1995@hotmail.com

Repository:
[LightweightBlockCiphers.Thesis.2018](https://github.com/jcsf/LightweightBlockCiphers.Thesis.2018)

-------------------------------------------------------------------------------

# Block Ciphers:

All block ciphers implementations have been made from the reference implementations of the ciphers.

* [AES](AES_128_128_v02/source):
    * **Description:** FELICS Implementation, T-Box AES Implementation
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [AES](AES_128_128_v08/source):
    * **Description:** T-Box AES implementation with cycle for rounds
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [AES](AES_128_128_v09/source):
    * **Description:** T-Box Compressed AES Implementation with cycle for rounds (12 Tables to 3)
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [AES](AES_128_128_v10/source):
    * **Description:** T-Box Compressed AES Compact Implementation (No Function Calls only Permutations and Cyles)
    * **Block:** 128 bits
    * **Key Size:** 128 bits
    
* [PRESENT](PRESENT_64_80_v02/source)
    * **Description:** FELICS Implementation, Software Optimized
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [RECTANGLE](RECTANGLE_64_80_v10/source)
    * **Description:** FELICS Optimized Implementation
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [RECTANGLE](RECTANGLE_64_128_v10/source)
    * **Description:** FELICS Optimized Implementation
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [CLEFIA](CLEFIA_128_128_v01/source)
    * **Description:** Based on Reference Implementation
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA](CLEFIA_128_128_v02/source)
    * **Description:** Code Cleaned from Reference Implementation
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA](CLEFIA_128_128_v03/source)
    * **Description:** T-Box Implementation
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA](CLEFIA_128_128_v04/source)
    * **Description:** 32-bits Oriented Implementation
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA](CLEFIA_128_128_v05/source)
    * **Description:** 32-bits Oriented Implementation, With Constants Table
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA](CLEFIA_128_128_v06/source)
    * **Description:** 32-bits Oriented Implementation, With T-Box and Constants Table
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA](CLEFIA_128_128_v07/source)
    * **Description:** 32-bits Oriented Implementation, With T-Box (Reduction from 8 to 4) and Constants Table
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA](CLEFIA_128_128_v08/source)
    * **Description:** 32-bits Oriented Implementation, With T-Box Reduction and Constants Table, F0 and F1 inlined
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA](CLEFIA_128_128_v09/source)
    * **Description:** 32-bits Oriented Implementation, With T-Box Reduction and Constants Table, Full Unroll
    * **Block:** 128 bits
    * **Key Size:** 128 bits
    
* [NOEKEON](NOEKEON_128_128_v01/source)
    * **Description:** Direct Key Implementation (Based on Reference), Big Endian Version
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON](NOEKEON_128_128_v02/source)
    * **Description:** Indirect Key Implementation (Based on Reference), Big Endian Version
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON](NOEKEON_128_128_v03/source)
    * **Description:** Direct Key Implementation, Little Endian Version
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON](NOEKEON_128_128_v04/source)
    * **Description:** Indirect Key Implementation, Little Endian Version
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [HALKA](Halka_64_80_v01/source):
    * **Description:** Based on Reference Implementation
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [HALKA](Halka_64_80_v02/source):
    * **Description:** Optimized Implementation (Code Cleaned)
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [SPECK](Speck_64_128_v07/source)
    * **Description:** Implementation from scratch
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPECK](Speck_128_128_v01/source)
    * **Description:** Implementation from scratch
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [SPARX](SPARX_64_128_v36/source)
    * **Description:** FELICS Reference Implementation.
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPARX](SPARX_128_128_v02/source)
    * **Description:** FELICS Reference Implementation.
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [ROADRUNNER](RoadRunneR_64_80_v03/source)
    * **Description:** Implementation using only one key scheduler
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [ROADRUNNER](RoadRunneR_64_128_v07/source)
    * **Description:** Implementation using only one key scheduler
    * **Block:** 64 bits
    * **Key Size:** 128 bits
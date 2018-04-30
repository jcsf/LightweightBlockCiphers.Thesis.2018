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

* [AES](AES_128_128_v11/source):
    * **Description:** T-Box Compressed AES Implementation, Full Unroll
    * **Block:** 128 bits
    * **Key Size:** 128 bits
    
* [PRESENT](PRESENT_64_80_v02/source)
    * **Description:** FELICS Implementation, Software Optimized
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [RECTANGLE-K80_v10](RECTANGLE_64_80_v10/source)
    * **Description:** FELICS Optimized Implementation
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [RECTANGLE-K128_v10](RECTANGLE_64_128_v10/source)
    * **Description:** FELICS Reference Optimized Implementation
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [RECTANGLE-K128_v11](RECTANGLE_64_128_v11/source)
    * **Description:** 32-bits parcial implementation
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [RECTANGLE-K128_v11](RECTANGLE_64_128_v12/source)
    * **Description:** 32-bits parcial implementation, Full Unroll
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [RECTANGLE-K128_v13](RECTANGLE_64_128_v13/source)
    * **Description:** 32-bits parcial implementation, State in Register Variables
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [RECTANGLE-K128_v14](RECTANGLE_64_128_v14/source)
    * **Description:** 32-bits parcial implementation, State in Register Variables, Full Unroll
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
    
* [NOEKEON_v01](NOEKEON_128_128_v01/source)
    * **Description:** Direct Key Implementation (Based on Reference), Big Endian Version
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_v02](NOEKEON_128_128_v02/source)
    * **Description:** Indirect Key Implementation (Based on Reference), Big Endian Version
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_v03](NOEKEON_128_128_v03/source)
    * **Description:** Direct Key Implementation, Little Endian Version
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_v04](NOEKEON_128_128_v04/source)
    * **Description:** Indirect Key Implementation, Little Endian Version
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_v05](NOEKEON_128_128_v05/source)
    * **Description:** Direct Key Implementation, Little Endian Version, With Constants Table
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_v06](NOEKEON_128_128_v06/source)
    * **Description:** Direct Key Implementation, Little Endian Version, No Function Calls
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_v07](NOEKEON_128_128_v07/source)
    * **Description:** Direct Key Implementation, Little Endian Version, No Function Calls, With Constants Table
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_v08](NOEKEON_128_128_v08/source)
    * **Description:** Direct Key Implementation, Little Endian Version, No Function Calls, Full Unroll
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_v09](NOEKEON_128_128_v09/source)
    * **Description:** Direct-Key Implementation, Little Endian Version, No Function Calls, Implementation in Registers Variables
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_v10](NOEKEON_128_128_v10/source)
    * **Description:** Direct-Key Implementation, Little Endian Version, No Function Calls, With Constants Table, Implementation in Registers Variables
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_v11](NOEKEON_128_128_v11/source)
    * **Description:** Direct-Key Implementation, Little Endian Version, With Constants Table, Implementation in Registers Variables
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_v12](NOEKEON_128_128_v12/source)
    * **Description:** Direct-Key Implementation, Little Endian Version, No Function Calls, Implementation in Registers Variables, Full Unroll
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

* [SPECK-64_v07](Speck_64_128_v07/source)
    * **Description:** Normal Implementation
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPECK-64_v08](Speck_64_128_v08/source)
    * **Description:** Normal Implementation, Full Unroll
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPECK-64_v09](Speck_64_128_v09/source)
    * **Description:** State in Register Variables Implementation
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPECK-64_v10](Speck_64_128_v10/source)
    * **Description:** State in Register Variables Implementation, Full Unroll
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPECK-128_v01](Speck_128_128_v01/source)
    * **Description:** Normal Implementation
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

* [ROADRUNNER](RoadRunneR_64_128_v08/source)
    * **Description:** Implementation using no key scheduler
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER](RoadRunneR_64_128_v09/source)
    * **Description:** Implementation 32-bits partial oriented, one key scheduler
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER](RoadRunneR_64_128_v10/source)
    * **Description:** Implementation 32-bits partial oriented, no key scheduler
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER](RoadRunneR_64_128_v11/source)
    * **Description:** Implementation 32-bits partial oriented, one key scheduler, no function calls
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER](RoadRunneR_64_128_v12/source)
    * **Description:** Implementation 32-bits partial oriented, no key scheduler, no function calls
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER](RoadRunneR_64_128_v13/source)
    * **Description:** Implementation 32-bits partial oriented, one key scheduler, full unroll
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER](RoadRunneR_64_128_v14/source)
    * **Description:** Implementation 32-bits partial oriented, no key scheduler, full unroll
    * **Block:** 64 bits
    * **Key Size:** 128 bits
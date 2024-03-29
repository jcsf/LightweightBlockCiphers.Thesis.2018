# LightweightBlockCiphers.Thesis.2018
Block Ciphers implemented for the Master Thesis@IST
(2017/2018)

João Fernandes, 87786, jcsf_1995@hotmail.com

Repository:
[LightweightBlockCiphers.Thesis.2018](https://github.com/jcsf/LightweightBlockCiphers.Thesis.2018)

-------------------------------------------------------------------------------

# Block Ciphers:

All block ciphers implementations have been made from the reference implementations of the ciphers.

* [AES_128_128_v01](AES_128_128_v01/source):
    * **Description:** FELICS Implementation, AES Normal
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [AES_128_128_v08](AES_128_128_v08/source):
    * **Description:** T-Box AES implementation with cycle for rounds
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [AES_128_128_v09](AES_128_128_v09/source):
    * **Description:** T-Box Compressed (12 Tables to 3) AES Compact Implementation (Permutations and Cycles)
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [AES_128_128_v10](AES_128_128_v10/source):
    * **Description:** T-Box Compressed AES Compact Implementation (No Permutations)
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [AES_128_128_v11](AES_128_128_v11/source):
    * **Description:** T-Box Compressed AES Implementation, Full Unroll
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [AES_128_128_v12](AES_128_128_v12/source):
    * **Description:** T-Box Compressed AES Compact Implementation (No Permutations), State in Registers
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [AES_128_128_v13](AES_128_128_v13/source):
    * **Description:** T-Box Compressed AES Implementation, State in Registers, Full Unroll
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [AES_128_128_v14](AES_128_128_v14/source):
    * **Description:** Reference Implementation
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [AES_128_128_v15](AES_128_128_v15/source):
    * **Description:** Reference Implementation, Fast Encryption (Multiply)
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA_128_128_v01](CLEFIA_128_128_v01/source)
    * **Description:** Based on Reference Implementation
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA_128_128_v02](CLEFIA_128_128_v02/source)
    * **Description:** Code Cleaned from Reference Implementation
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA_128_128_v03](CLEFIA_128_128_v03/source)
    * **Description:** T-Box Implementation
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA_128_128_v04](CLEFIA_128_128_v04/source)
    * **Description:** 32-bits Oriented Implementation
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA_128_128_v05](CLEFIA_128_128_v05/source)
    * **Description:** 32-bits Oriented Implementation, With Constants Table
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA_128_128_v06](CLEFIA_128_128_v06/source)
    * **Description:** 32-bits Oriented Implementation, With T-Box and Constants Table
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA_128_128_v07](CLEFIA_128_128_v07/source)
    * **Description:** 32-bits Oriented Implementation, With T-Box (Reduction from 8 to 4) and Constants Table
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA_128_128_v08](CLEFIA_128_128_v08/source)
    * **Description:** 32-bits Oriented Implementation, With T-Box Reduction and Constants Table, F0 and F1 inlined
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA_128_128_v09](CLEFIA_128_128_v09/source)
    * **Description:** 32-bits Oriented Implementation, With T-Box Reduction and Constants Table, Full Unroll
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA_128_128_v10](CLEFIA_128_128_v10/source)
    * **Description:** 32-bits Oriented Implementation, With T-Box Reduction and Constants Table, State in Registers
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [CLEFIA_128_128_v11](CLEFIA_128_128_v11/source)
    * **Description:** 32-bits Oriented Implementation, With T-Box Reduction and Constants Table, State in Registers, Full Unroll
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

* [NOEKEON_128_128_v01](NOEKEON_128_128_v01/source)
    * **Description:** Direct Key Implementation (Based on Reference), Big Endian Version
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_128_128_v02](NOEKEON_128_128_v02/source)
    * **Description:** Indirect Key Implementation (Based on Reference), Big Endian Version
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_128_128_v03](NOEKEON_128_128_v03/source)
    * **Description:** Direct Key Implementation, Little Endian Version
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_128_128_v04](NOEKEON_128_128_v04/source)
    * **Description:** Indirect Key Implementation, Little Endian Version
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_128_128_v05](NOEKEON_128_128_v05/source)
    * **Description:** Direct Key Implementation, Little Endian Version, With Constants Table
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_128_128_v06](NOEKEON_128_128_v06/source)
    * **Description:** Direct Key Implementation, Little Endian Version, No Function Calls
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_128_128_v07](NOEKEON_128_128_v07/source)
    * **Description:** Direct Key Implementation, Little Endian Version, No Function Calls, With Constants Table
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_128_128_v08](NOEKEON_128_128_v08/source)
    * **Description:** Direct Key Implementation, Little Endian Version, No Function Calls, Full Unroll
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_128_128_v09](NOEKEON_128_128_v09/source)
    * **Description:** Direct-Key Implementation, Little Endian Version, No Function Calls, With Constants Table, Implementation in Registers Variables
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_128_128_v10](NOEKEON_128_128_v10/source)
    * **Description:** Direct-Key Implementation, Little Endian Version, No Function Calls, Constants Computed on the Fly, Implementation in Registers Variables
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_128_128_v11](NOEKEON_128_128_v11/source)
    * **Description:** Direct-Key Implementation, Little Endian Version, With Constants Table, Only 1 Function For Encryption and Decryption, Implementation in Registers Variables
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [NOEKEON_128_128_v12](NOEKEON_128_128_v12/source)
    * **Description:** Direct-Key Implementation, Little Endian Version, No Function Calls, With Constants Table, Implementation in Registers Variables, Full Unroll
    * **Block:** 128 bits
    * **Key Size:** 128 bits
    
* [PRESENT_64_80_v01](PRESENT_64_80_v01/source)
    * **Description:** FELICS Reference Implementation
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [PRESENT_64_80_v07](PRESENT_64_80_v07/source)
    * **Description:** 32-bits oriented implementation (SBox 4-bits)
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [PRESENT_64_80_v08](PRESENT_64_80_v08/source)
    * **Description:** 32-bits oriented implementation (SBox 8-bits)
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [PRESENT_64_80_v09](PRESENT_64_80_v09/source)
    * **Description:** 32-bits oriented implementation (SBox 4-bits), Unroll Permutations
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [PRESENT_64_80_v10](PRESENT_64_80_v10/source)
    * **Description:** 32-bits oriented implementation (SBox 8-bits), Unroll Permutations
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [PRESENT_64_80_v11](PRESENT_64_80_v11/source)
    * **Description:** 32-bits oriented implementation (SBox 8-bits), State in Registers
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [PRESENT_64_80_v12](PRESENT_64_80_v12/source)
    * **Description:** 32-bits oriented implementation (SBox 8-bits), State in Registers, Unroll Permutations
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [PRESENT_64_80_v13](PRESENT_64_80_v13/source)
    * **Description:** 32-bits oriented implementation (SBox 8-bits), State in Registers, Unroll Permutations, Full Unroll
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [RECTANGLE_64_128_v10](RECTANGLE_64_80_v10/source)
    * **Description:** FELICS Optimized Implementation, No Function Calls
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [RECTANGLE_64_128_v01](RECTANGLE_64_128_v01/source)
    * **Description:** FELICS Reference Implementation
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [RECTANGLE_64_128_v10](RECTANGLE_64_128_v10/source)
    * **Description:** FELICS Optimized Implementation, No Function Calls
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [RECTANGLE_64_128_v11](RECTANGLE_64_128_v11/source)
    * **Description:** 32-bits parcial implementation
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [RECTANGLE_64_128_v12](RECTANGLE_64_128_v12/source)
    * **Description:** 32-bits parcial implementation, No Function Calls
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [RECTANGLE_64_128_v13](RECTANGLE_64_128_v13/source)
    * **Description:** 32-bits parcial implementation, No Function Calls, Full Unroll
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [RECTANGLE_64_128_v14](RECTANGLE_64_128_v14/source)
    * **Description:** 32-bits parcial implementation, State in Register Variables
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [RECTANGLE_64_128_v15](RECTANGLE_64_128_v15/source)
    * **Description:** 32-bits parcial implementation, State in Register Variables, Full Unroll
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER_64_80_v03](RoadRunneR_64_80_v03/source)
    * **Description:** Implementation using only one key scheduler
    * **Block:** 64 bits
    * **Key Size:** 80 bits

* [ROADRUNNER_64_128_v07](RoadRunneR_64_128_v07/source)
    * **Description:** Implementation using only one key scheduler
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER_64_128_v08](RoadRunneR_64_128_v08/source)
    * **Description:** Implementation using no key scheduler
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER_64_128_v09](RoadRunneR_64_128_v09/source)
    * **Description:** Implementation 32-bits partial oriented, one key scheduler
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER_64_128_v10](RoadRunneR_64_128_v10/source)
    * **Description:** Implementation 32-bits partial oriented, no key scheduler
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER_64_128_v11](RoadRunneR_64_128_v11/source)
    * **Description:** Implementation 32-bits partial oriented, one key scheduler, no function calls
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER_64_128_v12](RoadRunneR_64_128_v12/source)
    * **Description:** Implementation 32-bits partial oriented, no key scheduler, no function calls
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER_64_128_v13](RoadRunneR_64_128_v13/source)
    * **Description:** Implementation 32-bits partial oriented, one key scheduler, Full Unroll
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER_64_128_v14](RoadRunneR_64_128_v14/source)
    * **Description:** Implementation 32-bits partial oriented, no key scheduler, Full Unroll
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER_64_128_v15](RoadRunneR_64_128_v15/source)
    * **Description:** Implementation 32-bits partial oriented, one key scheduler, no function calls, SLK with Registers
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER_64_128_v16](RoadRunneR_64_128_v16/source)
    * **Description:** Implementation 32-bits partial oriented, no key scheduler, no function calls, SLK with Registers
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER_64_128_v17](RoadRunneR_64_128_v17/source)
    * **Description:** Implementation 32-bits partial oriented, one key scheduler, no function calls, SLK with Registers, Full Unroll
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [ROADRUNNER_64_128_v18](RoadRunneR_64_128_v18/source)
    * **Description:** Implementation 32-bits partial oriented, no key scheduler, no function calls, SLK with Registers, Full Unroll
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPARX_64_128_v36](SPARX_64_128_v36/source)
    * **Description:** FELICS Reference Implementation.
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPARX_64_128_v37](SPARX_64_128_v37/source)
    * **Description:** SPARX 32-Bit Oriented with Speckey w/ Pointers
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPARX_64_128_v38](SPARX_64_128_v38/source)
    * **Description:** SPARX 32-Bit Oriented with Speckey w/ Return Value
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPARX_64_128_v39](SPARX_64_128_v39/source)
    * **Description:** SPARX 32-Bit Oriented with Speckey Inlined (No Function Calls)
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPARX_64_128_v40](SPARX_64_128_v40/source)
    * **Description:** SPARX 32-Bit Oriented with Speckey Inlined (No Function Calls), Full Unroll
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPARX_64_128_v41](SPARX_64_128_v41/source)
    * **Description:** SPARX 32-Bit Oriented with Speckey Inlined (No Function Calls), State in Registers, Steps in Cycles
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPARX_64_128_v42](SPARX_64_128_v42/source)
    * **Description:** SPARX 32-Bit Oriented with Speckey Inlined (No Function Calls), State in Registers
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPARX_64_128_v43](SPARX_64_128_v43/source)
    * **Description:** SPARX 32-Bit Oriented with Speckey Inlined (No Function Calls), State in Registers, Full Unroll
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPARX_128_128_v02](SPARX_128_128_v02/source)
    * **Description:** FELICS Reference Implementation.
    * **Block:** 128 bits
    * **Key Size:** 128 bits

* [SPECK_64_128_v07](Speck_64_128_v07/source)
    * **Description:** Normal Implementation
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPECK_64_128_v08](Speck_64_128_v08/source)
    * **Description:** Normal Implementation, Full Unroll
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPECK_64_128_v09](Speck_64_128_v09/source)
    * **Description:** State in Register Variables Implementation
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPECK_64_128_v10](Speck_64_128_v10/source)
    * **Description:** State in Register Variables Implementation, Changed Cycle Operations on Decryption
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPECK_64_128_v11](Speck_64_128_v11/source)
    * **Description:** State in Register Variables Implementation, Full Unroll
    * **Block:** 64 bits
    * **Key Size:** 128 bits

* [SPECK_128_128_v01](Speck_128_128_v01/source)
    * **Description:** Normal Implementation
    * **Block:** 128 bits
    * **Key Size:** 128 bits

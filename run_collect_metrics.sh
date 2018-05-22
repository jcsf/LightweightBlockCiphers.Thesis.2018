# Reference Ciphers
ciphers="AES_128_128_v02 PRESENT_64_80_v02 CLEFIA_128_128_v01 Speck_64_128_v01 RECTANGLE_64_128_v10 SPARX_64_128_v36 RoadRunneR_64_128_v02 NOEKEON_128_128_v03 NOEKEON_128_128_v04 Halka_64_80_v01"

# Comparision Between Different Key Sizes
# RECTANGLE
ciphers="RECTANGLE_64_80_v10 RECTANGLE_64_128_v10"
# RoadRunneR
ciphers="RoadRunneR_64_80_v03 RoadRunneR_64_128_v07"

# Comparision Between Different Block Sizes
# SPARX
ciphers="SPARX_64_128_v36 SPARX_128_128_v02"
# SPECK
ciphers="Speck_64_128_v07 Speck_128_128_v01"

# Comparision Between CLEFIA Normal, CLEFIA 32-Bits, CLEFIA Constants Table, CLEFIA T-Box, CLEFIA T-Box Reduction, CLEFIA F-functions inline, CLEFIA Full Unroll, CLEFIA Register Variables
ciphers="CLEFIA_128_128_v02 CLEFIA_128_128_v04 CLEFIA_128_128_v05 CLEFIA_128_128_v06 CLEFIA_128_128_v07 CLEFIA_128_128_v08 CLEFIA_128_128_v09 CLEFIA_128_128_v10 CLEFIA_128_128_v11"

# Comparision Between AES Normal, AES T-Box Round Cycle, AES Reduced T-Box Round Cycle, AES Compact T-Box, AES Reduced T-Box Full Unroll, AES Reduced T-Box State in Registers, Full Unroll
ciphers="AES_128_128_v01 AES_128_128_v08 AES_128_128_v09 AES_128_128_v10 AES_128_128_v11 AES_128_128_v12 AES_128_128_v13"

# Comparision Between RoadRunner Reference Implementation, RoadRunner One Key Scheduler, RoadRunner No Key Scheduler, RoadRunner 32-bits parcial implementation, RoadRunneR No Function Calls, RoadRunner Full Unroll, RoadRunneR SLK Registers
ciphers="RoadRunneR_64_128_v02 RoadRunneR_64_128_v07 RoadRunneR_64_128_v08 RoadRunneR_64_128_v09 RoadRunneR_64_128_v10 RoadRunneR_64_128_v11 RoadRunneR_64_128_v12 RoadRunneR_64_128_v13 RoadRunneR_64_128_v14 RoadRunneR_64_128_v15 RoadRunneR_64_128_v16 RoadRunneR_64_128_v17 RoadRunneR_64_128_v18"

# Comparision Between NOEKEON Normal, NOEKEON With Constants Table
ciphers="NOEKEON_128_128_v03 NOEKEON_128_128_v04 NOEKEON_128_128_v05 NOEKEON_128_128_v06 NOEKEON_128_128_v07 NOEKEON_128_128_v08 NOEKEON_128_128_v09 NOEKEON_128_128_v10 NOEKEON_128_128_v11 NOEKEON_128_128_v12"

# Comparision Between RECTANGLE Reference Implementation, Optimized Reference Implementation, RECTANGLE 32-Bits Parcial, RECTANGLE No Function Calls, RECTANGLE Full Unroll, RECTANGLE Register Variables, RECTANGLE Register Variables Unroll
ciphers="RECTANGLE_64_128_v01 RECTANGLE_64_128_v10 RECTANGLE_64_128_v11 RECTANGLE_64_128_v12 RECTANGLE_64_128_v13 RECTANGLE_64_128_v14 RECTANGLE_64_128_v15"

# Comparision Between SPECK Reference Implementation, SPECK Full Unroll, SPECK Register Variables, SPECK Register Variables Unroll
ciphers="Speck_64_128_v07 Speck_64_128_v08 Speck_64_128_v09 Speck_64_128_v10"

# Comparision Between SPARX Normal, SPARX 32-bits Speckey w/ Pointers, SPARX 32-bits Speckey w/ Return Value, SPARX 32-bits Speckey Inlined, SPARX 32-bits Full Unroll, SPARX 32-bits State In Registers and Steps in Cycles, SPARX 32-bits State in Registers, SPARX 32-bits State in Registers Full Unroll
ciphers="SPARX_64_128_v36 SPARX_64_128_v37 SPARX_64_128_v38 SPARX_64_128_v39 SPARX_64_128_v40 SPARX_64_128_v41 SPARX_64_128_v42 SPARX_64_128_v43"

# PRESENT Optimizations
ciphers="PRESENT_64_80_v01 PRESENT_64_80_v07 PRESENT_64_80_v08 PRESENT_64_80_v09 PRESENT_64_80_v10 PRESENT_64_80_v11 PRESENT_64_80_v12 PRESENT_64_80_v13"

# Current Ciphers
#ciphers="CLEFIA_128_128_v02 CLEFIA_128_128_v04 CLEFIA_128_128_v05 CLEFIA_128_128_v06 CLEFIA_128_128_v07 CLEFIA_128_128_v08 CLEFIA_128_128_v09 CLEFIA_128_128_v10 CLEFIA_128_128_v11 AES_128_128_v02 AES_128_128_v08 AES_128_128_v09 AES_128_128_v10 AES_128_128_v11 RoadRunneR_64_128_v02 RoadRunneR_64_128_v07 RoadRunneR_64_128_v08 RoadRunneR_64_128_v09 RoadRunneR_64_128_v10 RoadRunneR_64_128_v11 RoadRunneR_64_128_v12 RoadRunneR_64_128_v13 RoadRunneR_64_128_v14 RoadRunneR_64_128_v15 RoadRunneR_64_128_v16 RoadRunneR_64_128_v17 RoadRunneR_64_128_v18 NOEKEON_128_128_v03 NOEKEON_128_128_v04 NOEKEON_128_128_v05 NOEKEON_128_128_v06 NOEKEON_128_128_v07 NOEKEON_128_128_v08 NOEKEON_128_128_v09 NOEKEON_128_128_v10 NOEKEON_128_128_v11 NOEKEON_128_128_v12 RECTANGLE_64_128_v10 RECTANGLE_64_128_v11 RECTANGLE_64_128_v12 RECTANGLE_64_128_v13 RECTANGLE_64_128_v14 Speck_64_128_v07 Speck_64_128_v08 Speck_64_128_v09 Speck_64_128_v10 SPARX_64_128_v36 SPARX_64_128_v37 SPARX_64_128_v38 SPARX_64_128_v39 SPARX_64_128_v40 SPARX_64_128_v41 SPARX_64_128_v42 SPARX_64_128_v43"

#ciphers="Speck_64_128_v07 Speck_64_128_v08 Speck_64_128_v09 Speck_64_128_v10 Speck_64_128_v11 Speck_64_128_v12"

cd /home/felics/FELICS/FELICS_v1.1.23/block_ciphers/scripts/

for i in $ciphers; do
    find ../source/ciphers/$i/build -type f -not -name '.gitignore' -delete
done

./collect_ciphers_metrics.sh -f='5' -a='ARM' --scenarios='1' --ciphers="$ciphers"

for i in $ciphers; do
    find ../source/ciphers/$i/build -type f -not -name '.gitignore' -delete
    find ../source/ciphers/$i/source -type f -name 'cipher.bin' -delete
done

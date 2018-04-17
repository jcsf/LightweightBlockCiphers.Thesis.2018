# Reference Ciphers
#ciphers="AES_128_128_v02 PRESENT_64_80_v02 CLEFIA_128_128_v01 Speck_64_128_v01 RECTANGLE_64_128_v10 SPARX_64_128_v36 RoadRunneR_64_128_v02 NOEKEON_128_128_v03 NOEKEON_128_128_v04 Halka_64_80_v01"

# Comparision Between Different Key Sizes
# RECTANGLE
#ciphers="RECTANGLE_64_80_v10 RECTANGLE_64_128_v10"
# RoadRunneR
#ciphers="RoadRunneR_64_80_v03 RoadRunneR_64_128_v07"

# Comparision Between Different Block Sizes
# SPARX
#ciphers="SPARX_64_128_v36 SPARX_128_128_v02"
# SPECK
#ciphers="Speck_64_128_v07 Speck_128_128_v01"

# Comparision Between CLEFIA Normal, CLEFIA 32-Bits, CLEFIA Constants Table, CLEFIA T-Box, CLEFIA T-Box Reduction, CLEFIA F-functions inline, CLEFIA Full Unroll
ciphers="CLEFIA_128_128_v02 CLEFIA_128_128_v04 CLEFIA_128_128_v05 CLEFIA_128_128_v06 CLEFIA_128_128_v07 CLEFIA_128_128_v08 CLEFIA_128_128_v09"

# Comparision Between AES T-Box Full Unroll, AES T-Box Round Cycle, AES Reduced T-Box Round Cycle, AES Compact T-Box, AES Reduced T-Box Full Unroll
ciphers="AES_128_128_v02 AES_128_128_v08 AES_128_128_v09 AES_128_128_v10 AES_128_128_v11"

# Current Ciphers
#ciphers="AES_128_128_v02 PRESENT_64_80_v02 CLEFIA_128_128_v02 Speck_64_128_v07 RECTANGLE_64_128_v10 SPARX_64_128_v36 RoadRunneR_64_128_v07 NOEKEON_128_128_v03 NOEKEON_128_128_v04 Halka_64_80_v02"

cd /home/felics/FELICS/FELICS_v1.1.23/block_ciphers/scripts/
./collect_ciphers_metrics.sh -f='3' -a='ARM' --scenarios='1' --ciphers="$ciphers"

for i in $ciphers; do
    find ../source/ciphers/$i/build -type f -not -name '.gitignore' -delete
    find ../source/ciphers/$i/source -type f -name 'cipher.bin' -delete
done

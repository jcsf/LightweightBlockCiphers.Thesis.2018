# $1 - Cipher
# $2 - Senario
# $3 - Compiler Option
# $4 - Execute Mode (On/Off)

cd /home/felics/FELICS/FELICS_v1.1.23/block_ciphers/source/ciphers/$1/source
make -f ./../../../common/cipher.mk cleanall

if [ $4 = 1 ]
then
    make -f ./../../../common/cipher.mk DEBUG=7 ARCHITECTURE=ARM SCENARIO=$2 COMPILER_OPTIONS=$3 
    make -f ./../../../common/cipher.mk ARCHITECTURE=ARM SCENARIO=$2 COMPILER_OPTIONS=$3 upload-cipher
    ./../../../../../common/scripts/arm/arm_serial_terminal.py
fi

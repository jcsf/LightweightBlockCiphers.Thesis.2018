# $1 - Cipher
# $2 - Senario
# $3 - Execute Mode (On/Off)

cd /home/felics/FELICS/FELICS_v1.1.23/block_ciphers/source/ciphers/$1/source
make -f ./../../../common/cipher.mk cleanall

if [ $3 = 1 ]
then
    make -f ./../../../common/cipher.mk DEBUG=7 ARCHITECTURE=PC SCENARIO=$2

	if [ $2 = 0 ]
	then
		./../build/cipher.elf
	fi

	if [ $2 -gt 0 ]
	then
		./../build/scenario$2.elf
	fi
fi

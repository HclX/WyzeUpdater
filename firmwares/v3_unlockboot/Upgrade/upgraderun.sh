#!/bin/sh
SCRIPT=`readlink -f $0`
SCRIPT_DIR=`dirname $SCRIPT`

SD_DIR=/media/mmcblk0p1
if [ ! -d $SD_DIR ];
then
  SD_DIR=/media/mmc
fi

if [ ! -d $SD_DIR ];
then
  SD_DIR=/tmp
fi

exec >> $SD_DIR.log 2>&1

dd if=/dev/mtdblock0 of=/tmp/boot.bin
cp /tmp/boot.bin $SD_DIR/original.bin

if ! echo '5cd21257d6a23da5833caf37e1971e2c  /tmp/boot.bin' | md5sum -c
then
  echo "Incorrect original bootloader hash!"
  sync
  return 0
fi

printf '\x00\x00' | dd conv=notrunc of=/tmp/boot.bin bs=1 seek=$((0x210CC))
cp /tmp/boot.bin $SD_DIR/modified.bin

if ! echo 'cfdb1780cb9cda7c12bebab2e17cbc91  /tmp/boot.bin' | md5sum -c
then
  echo "Incorrect modified bootloader hash!"
  sync
  return 0
fi

echo "Writing modified bootloader..."
dd if=/tmp/boot.bin of=/dev/mtdblock0

echo "Done..."
sync

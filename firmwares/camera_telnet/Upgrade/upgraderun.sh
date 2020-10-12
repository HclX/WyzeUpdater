#!/bin/sh
SCRIPT=`readlink -f $0`
SCRIPT_DIR=`dirname $SCRIPT`

SD_DIR=/media/mmcblk0p1
if [ ! -d $SD_DIR ];
then
    SD_DIR=/media/mmc
fi

if [ -d $SD_DIR/debug ];
then
    rm -rf $SD_DIR/debug/system
    rm -rf $SD_DIR/debug/etc

    # Copying system and etc back to SD card for analysis
    cp -rL /system $SD_DIR/debug
    cp -rL /etc $SD_DIR/debug
fi

umount /etc
rm -rf /tmp/etc
cp -r /etc /tmp/

PASSWD_SHADOW="root::10933:0:99999:7:::"
echo $PASSWD_SHADOW >/tmp/etc/shadow

mount -o bind /tmp/etc /etc

if [ "$SCRIPT_DIR" != "/system/init" ];
then
  cp $0 /system/init/run_telnet.sh
  echo "#/system/init/run_telnet.sh &" >> /system/init/app_init.sh
fi

while true
do
  if ! pidof telnetd;
  then
    telnetd
  fi

  sleep 10
done

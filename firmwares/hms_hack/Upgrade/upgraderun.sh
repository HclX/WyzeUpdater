#!/bin/sh
APP_VER=$(grep -i AppVer /usr/app.ver | sed -E 's/^.*=[[:space:]]*([0-9.]+)[[:space:]]*$/\1/g')
if [ "$APP_VER" != "4.33.1.40" ];
then
  echo "Incorrect root FS version: '$APP_VER', expecting '4.33.1.40'..."
  reboot
  exit 0
fi

cp /tmp/Upgrade/wyzehacks.sh /configs/
chmod a+x /configs/wyzehacks.sh

echo "erase para !!!!!!!!!!!"
flash_eraseall /dev/mtd7
sync
echo "write para !!!!!!!!!!!"
flashcp -v /tmp/Upgrade/PARA.null /dev/mtd7
sync
sync

echo "erase backa !!!!!!!!!!!"
flash_eraseall /dev/mtd5
sync
echo "write backa !!!!!!!!!!!"
flashcp -v /tmp/Upgrade/rootfs /dev/mtd5
sync

echo "erase para !!!!!!!!!!!"
flash_eraseall /dev/mtd7
sync
echo "write para !!!!!!!!!!!"
flashcp -v /tmp/Upgrade/PARA.rootfs /dev/mtd7
sync
sync

reboot

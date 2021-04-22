#!/bin/sh
tar --sort=name \
    --owner=root:0 \
    --group=root:0 \
    --mtime='1970-01-01' \
    --dereference \
    -cf /tmp/hms_telnet.bin Upgrade

 ./encrypt -e /tmp/hms_telnet.bin -o ../hms_telnet.bin
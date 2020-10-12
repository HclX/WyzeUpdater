#!/bin/sh

tar --sort=name --owner=root:0 --group=root:0 --mtime='1970-01-01' --dereference -cf ../camera_telnet.bin Upgrade

The latest Wyze HMS hub firmware has implemented encryption on OTA firmware. So
we have to encrypt the tar archive before pushing it to device. Luckily the
encryption is using a hardcoded key. By physically dumping the firwmare I was
able to extract the encryption key, and reverse the encryption algorithm and
implemented the same thing as a linux tool.

To build the encryption tool, you will need to install openssl and some
dependencies. Once you get there, simply run:
```
gcc encrypt.c -o encrypt -lcrypto
```

To run the tool, use the following command:
```
./encrypt -e <input_file> -o <output_file>`
```

This firmware is similiar to the `camera_telnet` one to enable temporary telnet
access to the hub. To build the firmware, run `build.sh` and the OTA update will
be generated as ../hms_telnet.bin

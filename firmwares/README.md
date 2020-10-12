"camera_telnet.bin" is a sample of custom firmware update designed to enable
telnetd on Wyze cameras. If runs successfully, the camera's telnetd will be
enabled temporarily (lost after reboot) with username `root` and no password.

To make it permanent, all you need is telnet into it and modify 
`/system/init/app_init.sh` by removing the comment before line
`/system/init/run_telnet.sh &`

WARNNING:
This will enable telnetd without password, so your camera will be in an
unsecured state. Anyone has your network access will be able to run stuff on
your camera. You can customize your own password by modifying the
`PASSWD_SHADOW` variable. To generate a shadow string from password, use the
following command:
```
  openssl passwd -1 -salt <YOUR SALT> <YOUR PASSWORD>
```

# WyzeUpdater
This is a tool capable of pushing arbitrary update images to wyze devices. It
works by simulating itself as Wyze app.

To use this tool, you will need to specify at least the target device's MAC
address, and the firmware file. While running, it will create a http(s) server
to serve the firmware binary. By specifying "--ssl" will make a https server
with a pre-generated self-signed certificate. This is necessary for the wyze
plugs since it only connects with https protocol. You can specify alternative
port to listen at. If not specified, default ones will be used, which means 80
for http, and 443 for https. Again, wyze plugs will only connect to https server
on port 443. When using default ports, you may need to run the script with root
privilege otherwise it will fail to start the service.

For the first time you will need to enter your wyze.com username and password,
and also do 2FA with primary phone. The login token will be cached in a file
named '.tokens' so you don't need to do this entire authentication again. Make
sure not to share this file with anyone you don't trust.

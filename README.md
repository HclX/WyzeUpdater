# WyzeUpdater
This is a tool capable of pushing arbitrary update images to wyze devices. It
works by simulating itself as Wyze app.

## Latest update
With latest Wyze server side change, now the update target has to be from one
of the following hosts:

* d1fk93tz4plczb.cloudfront.net
This is found used by V2 cameras. Here is a sample of the update URL:
https://d1fk93tz4plczb.cloudfront.net/UpgradeKit/1621505419/Upgrade_4.9.7.608_05200304.tar

* s3-us-west-2.amazonaws.com
This is found used by V3 cameras with something like the following:
https://s3-us-west-2.amazonaws.com/wuv2/upgrade/WYZE_CAKP2JFUS/firmware/4.36.3.19.tar

* d2h8pzxcxn71bo.cloudfront.net
This one is used by the WyzeSense Gateway (Home Monitoring System) in the
following form:
https://d2h8pzxcxn71bo.cloudfront.net/upgrade/GW3U/firmware/4.32.4.295.tar

Only URLs with the above form will be approved by the Wyze update server and
forwarded to the device side.

This also means you will need to use DNS spoofing otherwise even if it reaches
the device, the device won't be able to get your own firmware update package.

To make it worse, most of the devices (verified on V2/Pan latest version) are
also requiring the URL to be started with `https` and they verify the
corresponding SSL certificate. This basically makes this tool effectively dead
for those devices. Other still working devices might also do some validations
on the URL so you will need to change accordingly with the new "--url-host" and
'--url-path' flags for that.

Here is an example wyze_updater.py command line and the generated URL that
device will receive:

Command line:
```
./wyze_updater.py \
    --token ~/.wyze_token \
    update -d <hms_mac> -f firmwares/hms_telnet.bin \
    --url-host 'd1fk93tz4plczb.cloudfront.net' \
    --url-path 'upgrade/GW3U/firmware/4.32.4.295.tar' \
    -p 18080
```

URL received by the device:
```
http://d2h8pzxcxn71bo.cloudfront.net:18080/upgrade/GW3U/firmware/4.32.4.295.tar
```


## Usage
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

#!/usr/bin/env python3

import sys
import argparse
import time
import requests
import json
import logging
import base64
import hashlib
import uuid
import http.server, ssl
import os
import threading
import socket
from pprint import pprint

def check_rsp(rsp):
    pprint(rsp)
    if rsp['code'] != '1':
        raise RuntimeError('Request failed, error %s:%s' % (rsp['code'], rsp['msg']))

def wyze_login(email, password):
    for i in range(0, 3):
        password = hashlib.md5(password.encode('ascii')).hexdigest()

    phone_id = str(uuid.uuid4())

    headers = {
        'Phone-Id': phone_id,
        'User-Agent': 'wyze_android_2.11.40',
        'X-API-Key': 'RckMFKbsds5p6QY3COEXc2ABwNTYY0q18ziEiSEm',
    }

    payload = {'email':email, 'password':password}
    r = requests.post("https://auth-prod.api.wyze.com/user/login", headers=headers, json=payload)
    rsp = r.json()
    pprint(rsp)

    if not rsp['access_token']:
        params = {
            'mfaPhoneType': 'Primary',
            'sessionId': rsp['sms_session_id'],
            'userId': rsp['user_id'],
        }

        payload = {}
        r = requests.post('https://auth-prod.api.wyze.com/user/login/sendSmsCode', headers=headers, params=params, json=payload)
        rsp = r.json()
        pprint(rsp)

        session_id = rsp['session_id']
        verification_code = input("Enter the verification code:")

        print("verification code: %s" % verification_code)

        payload = {
            "email": email,
            "password": password,
            "mfa_type":"PrimaryPhone",
            "verification_id":rsp['session_id'],
            "verification_code":verification_code}

        r = requests.post("https://auth-prod.api.wyze.com/user/login", headers=headers, json=payload)
        rsp = r.json()
        pprint(rsp)
    
    return {
        'phone_id': phone_id,
        'user_id': rsp['user_id'],
        'access_token': rsp['access_token'],
        'refresh_token': rsp['refresh_token'],
    }

BASE_URL = "https://api.wyzecam.com"
SC = "a626948714654991afd3c0dbd7cdb901"
SV_GET_V2_DEVICE_INFO = "81d1abc794ba45a39fdd21233d621e84"
def get_device_info(creds, mac):
    url = BASE_URL + "/app/v2/device/get_device_Info"
    payload = {
        'access_token': creds['access_token'],
        "app_name": "com.hualai",
        "app_ver": "com.hualai___2.11.40",
        "app_version": "2.11.40",
        "phone_id": creds["phone_id"],
        "phone_system_type": "2",
        "sc": SC,
        "sv": SV_GET_V2_DEVICE_INFO,
        "ts": int(time.time()) * 1000,
        "device_mac": mac,
        "device_model": 'Unknown',
    }

    r = requests.post(url, headers={'User-Agent': 'okhttp/3.8.1'}, json=payload)
    rsp = r.json()
    check_rsp(rsp)

    return rsp['data']


def upgrade(creds, model, mac, upgrade_url, md5):
    SV_V2_RUN_ACTION = "011a6b42d80a4f32b4cc24bb721c9c96"
    url = BASE_URL + "/app/v2/auto/run_action"
    payload = {
        'access_token': creds['access_token'],
        "app_name": "com.hualai",
        "app_ver": "com.hualai___2.11.40",
        "app_version": "2.11.40",
        "phone_id": creds['phone_id'],
        "phone_system_type": "2",
        "sc": SC,
        "sv": SV_V2_RUN_ACTION,
        "ts": int(time.time()) * 1000,
        "provider_key": model,
        "action_key": "upgrade",
        "custom_string": "",
        "instance_id": mac,
        "action_params" : {
            "url": upgrade_url,
            "md5": md5,
            "model": model
        }
    }

    r = requests.post(url, headers={'User-Agent': 'okhttp/3.8.1'}, json=payload)
    rsp = r.json()
    check_rsp(rsp)

    return rsp['data']

def log_verbose():
    # These two lines enable debugging at httplib level (requests->urllib3->http.client)
    # You will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
    # The only thing missing will be the response.body which is not logged.
    try:
        import http.client as http_client
    except ImportError:
        # Python 2
        import httplib as http_client
    http_client.HTTPConnection.debuglevel = 1

    # You must initialize logging, otherwise you'll not see debug output.
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

def start_http_server(firmware_data, port, use_ssl):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            print("request received, path=%s" % self.path)
            self.send_response(200)
            self.send_header('Content-Disposition', 'attachment; filename=firmware.bin')
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Content-Length', len(firmware_data))
            self.end_headers()

            self.wfile.write(firmware_data)
            return

    if not port:
        port = 443 if use_ssl else 80

    server_address = ('', port)
    httpd = http.server.HTTPServer(server_address, Handler)  # http.server.SimpleHTTPRequestHandler)
    if use_ssl:
        httpd.socket = ssl.wrap_socket(httpd.socket,
                                    server_side=True,
                                    certfile='testcert/cert.pem',
                                    keyfile='testcert/key.pem',
                                    ssl_version=ssl.PROTOCOL_TLS)

    threading.Thread(target=httpd.serve_forever).start()
    return httpd

def get_host_ip(probe_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((probe_ip, 8888))
    return s.getsockname()[0]

def build_url(ip, use_ssl=False, port=None):
    if use_ssl:
        url = 'https://' + ip
    else:
        url = 'http://' + ip
    
    if port:
        url += ':%d' % port
    
    url += '/firmware.bin'
    return url


parser = argparse.ArgumentParser(description='Wyze product updater.')
parser.add_argument('--mac', required=True, help='MAC address of the target device.')
parser.add_argument('--user', help='User name of the associated wyze account.')
parser.add_argument('--password', help='Password of the associated wyze account.')
parser.add_argument('--firmware', required=True, help='Firmware file')
parser.add_argument('--ssl', action='store_true', help='Use HTTPS to serve the firmware data.')
parser.add_argument('--port', type=int, help='HTTP(S) serving port.')
parser.add_argument('--ip', help='HTTP(S) serving address.')

parser.add_argument('--verbose', action='store_true', help='Output debugging informaiton')
parser.set_defaults(verbose=False)

args = parser.parse_args()

if args.verbose:
    log_verbose()

try:
    with open('.tokens') as f:
        print("Using saved credentials from .tokens...")
        creds = json.load(f)
except OSError:
    creds = None

if not creds:
    print("No saved credentials found, logging in with username/password...")
    if not args.user:
        args.user = input("Please enter the account name:")
    
    if not args.password:
        args.password = input("Please enter the password:")

    creds = wyze_login(args.user, args.password)
    try:
        with open('.tokens', 'w') as f:
            json.dump(creds, f)
            print("Credentials saved to .tokens")
    except OSError:
        print("Failed to save credentials.")

print("Checking device, mac=%s" % args.mac)
try:
    dev_info = get_device_info(creds, args.mac)
except RuntimeError as e:
    print(e)

print('Device type:     ', dev_info['product_type'])
print('Device model:    ', dev_info['product_model'])
print('Device name:     ', dev_info['nickname'])
print('Firmware version:', dev_info['firmware_ver'])
print('IP Address:      ', dev_info['ip'])

firmware_data = open(args.firmware, 'rb').read()
md5 = hashlib.md5(firmware_data).hexdigest()

if not args.ip:
    args.ip = get_host_ip(dev_info['ip'])
url = build_url(args.ip, args.ssl, args.port)

server = start_http_server(firmware_data, args.port, args.ssl)

print("Sending firmware file '%s' as '%s', md5=%s" % (args.firmware, url, md5))
upgrade(creds, dev_info['product_model'], args.mac, url, md5)

print("Press Ctrl+C when the upgrade finished...")
try:
    while True:
        time.sleep(1)
        print(".", end="", flush=True)
except KeyboardInterrupt:
    pass

print("Stopping http server...")
server.shutdown()

print('Done.')

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
import errno
import threading
import socket
from pprint import pprint

def log_init(debugging):
    # These two lines enable debugging at httplib level (requests->urllib3->http.client)
    # You will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
    # The only thing missing will be the response.body which is not logged.
    try:
        import http.client as http_client
    except ImportError:
        # Python 2
        import httplib as http_client

    # You must initialize logging, otherwise you'll not see debug output.
    logging.basicConfig()
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.propagate = True

    if debugging:
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log.setLevel(logging.DEBUG)
        http_client.HTTPConnection.debuglevel = 1
    else:
        logging.getLogger().setLevel(logging.INFO)
        requests_log.setLevel(logging.INFO)

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
    rsp = requests.post(
        "https://auth-prod.api.wyze.com/user/login",
        headers=headers, json=payload).json()
    logging.debug(rsp)

    if not rsp['access_token']:
        if "TotpVerificationCode" in rsp.get("mfa_options"):

            print("Using TOTP app for 2FA")
            verification_code = input("Enter the verification code:")

            print("verification code: %s" % verification_code)

            payload = {
                "email": email,
                "password": password,
                "mfa_type":"TotpVerificationCode",
                "verification_id":rsp["mfa_details"]["totp_apps"][0]["app_id"],
                "verification_code":verification_code
            }

        else:
            params = {
                'mfaPhoneType': 'Primary',
                'sessionId': rsp['sms_session_id'],
                'userId': rsp['user_id'],
            }

            payload = {}
            rsp = requests.post(
                'https://auth-prod.api.wyze.com/user/login/sendSmsCode',
                headers=headers, params=params, json=payload).json()
            logging.debug(rsp)

            session_id = rsp['session_id']

            print("Using phone SMS for 2FA")
            verification_code = input("Enter the verification code:")

            print("verification code: %s" % verification_code)

            payload = {
                "email": email,
                "password": password,
                "mfa_type":"PrimaryPhone",
                "verification_id":rsp['session_id'],
                "verification_code":verification_code}

        rsp = requests.post(
            "https://auth-prod.api.wyze.com/user/login",
            headers=headers, json=payload).json()
        logging.debug(rsp)
    
    return {
        'phone_id': phone_id,
        'user_id': rsp['user_id'],
        'access_token': rsp['access_token'],
        'refresh_token': rsp['refresh_token'],
    }

APP_NAME = "com.hualai"
APP_VERSION = "2.11.40"
PHONE_SYSTEM_TYPE = "2"

BASE_URL = "https://api.wyzecam.com"
SC = "a626948714654991afd3c0dbd7cdb901"

def device_api(creds, url, sv, **params):
    payload = {
        'access_token': creds['access_token'],
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "phone_system_type": PHONE_SYSTEM_TYPE,
        "app_ver": APP_NAME + "___" + APP_VERSION,
        "phone_id": creds['phone_id'],
        "sc": SC,
        "sv": sv,
        "ts": int(time.time()) * 1000,
    }

    logging.debug(params)
    payload.update(params)

    rsp = requests.post(BASE_URL + url, headers={'User-Agent': 'okhttp/3.8.1'}, json=payload).json()
    logging.debug(rsp)
    if rsp['code'] != '1':
        raise RuntimeError('Request failed, error %s:%s' % (rsp['code'], rsp['msg']))

    return rsp['data']

def get_object_list(creds):
    URL_V2_GET_OBJECT_LIST = "/app/v2/home_page/get_object_list"
    SV_V2_GET_OBJECT_LIST = "c417b62d72ee44bf933054bdca183e77"
    return device_api(creds, URL_V2_GET_OBJECT_LIST, SV_V2_GET_OBJECT_LIST)

def get_device_info(creds, mac, model='Unknown'):
    URL_V2_GET_DEVICE_INFO = "/app/v2/device/get_device_info"
    SV_V2_GET_DEVICE_INFO = "81d1abc794ba45a39fdd21233d621e84"
    return device_api(creds, URL_V2_GET_DEVICE_INFO, SV_V2_GET_DEVICE_INFO, device_mac=mac, device_model=model)

def run_action(creds, provider, action, instance, params):
    URL_V2_RUN_ACTION = "/app/v2/auto/run_action"
    SV_V2_RUN_ACTION = "011a6b42d80a4f32b4cc24bb721c9c96"
    return device_api(
        creds, URL_V2_RUN_ACTION, SV_V2_RUN_ACTION,
        provider_key=provider, action_key=action, instance_id=instance,
        custom_string="", action_params=params)

def push_update(creds, model, mac, update_url, md5, ver):
    return run_action(creds, model, "upgrade", mac, {"url": update_url, "md5": md5, "model": model, "firmware_ver": ver})

def list_devices(creds, args):
    data = get_object_list(creds)
    devices = sorted(data['device_list'], key=lambda x:x['product_model'], reverse=True)
    for x in devices:
        if args.models and (x['product_model'] not in args.models):
            continue

        print("Device Type:       %s (%s)" % (x['product_type'], x['product_model']))
        print("Device MAC:        %s" % x['mac'])
        print("Firmware Version:  %s" % x['firmware_ver'])
        print("Device Name:       %s" % x['nickname'])
        print("IP:                %s" % x['device_params'].get('ip', 'n/a'))
        print()

def start_http_server(firmware_data, addr, port, use_ssl):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

        def do_GET(self):
            logging.debug("request received, path=%s" % self.path)
            self.send_response(200)
            self.send_header('Content-Disposition', 'attachment; filename=firmware.bin')
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Content-Length', len(firmware_data))
            self.end_headers()

            self.wfile.write(firmware_data)
            return

    if not port:
        port = 443 if use_ssl else 80

    server_address = (addr, port)
    httpd = http.server.HTTPServer(server_address, Handler)
    if use_ssl:
        httpd.socket = ssl.wrap_socket(httpd.socket,
                                    server_side=True,
                                    certfile='testcert/cert.pem',
                                    keyfile='testcert/key.pem',
                                    ssl_version=ssl.PROTOCOL_TLS)

    threading.Thread(target=httpd.serve_forever).start()
    return httpd

def get_host_ip(dest_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((dest_ip, 8888))
    return s.getsockname()[0]

def build_url(url_host, url_path, use_ssl=False, port=None):
    if use_ssl:
        url = 'https://' + url_host
    else:
        url = 'http://' + url_host
    
    if port:
        url += ':%d' % port
    
    if not url_path.startswith('/'):
        url_path = '/' + url_path

    url += url_path
    return url

def update_devices(creds, args):
    if args.models:
        data = get_device_list(creds)
        args.devices = [x['mac'] for x in data['device_list'] if x['product_model'] in args.models]

    firmware_data = open(args.firmware, 'rb').read()
    md5 = hashlib.md5(firmware_data).hexdigest()

    server = None
    for mac in args.devices:
        logging.info("Checking device, mac=%s" % mac)
        try:
            dev_info = get_device_info(creds, mac)
        except RuntimeError as e:
            print(e)
            continue

        # TODO: Skipping devices not having valid IP address
        print()
        print('Device type:      %s (%s)' % (dev_info['product_type'], dev_info['product_model']))
        print('Device name:      %s' % dev_info['nickname'])
        print('Firmware version: %s' % dev_info['firmware_ver'])
        print('IP Address:       %s' % dev_info['ip'])
        print()

        answer = input("Pushing firmware to this device? [y/N]:")
        if answer.upper() != 'Y':
            logging.info("Skipping device %s (%s)..." % (dev_info['nickname'], mac))
            continue

        if not server:
            if not args.addr:
                args.addr = get_host_ip(dev_info['ip'])

            if not args.url_host:
                args.url_host = args.addr
            
            if not args.url_path:
                args.url_path = "firmware.bin"
            
            if not args.firmware_ver:
                args.firmware_ver = "9.9.9.9"

            url = build_url(args.url_host, args.url_path, args.ssl, args.port)
            server = start_http_server(firmware_data, args.addr, args.port, args.ssl)
            logging.info("Serving firmware file '%s' as '%s', md5=%s" % (args.firmware, url, md5))

        push_update(creds, dev_info['product_model'], mac, url, md5, args.firmware_ver)
        time.sleep(3)

    if server:
        print("Press Ctrl+C when all the updates are done...")
        try:
            while True:
                time.sleep(1)
                print(".", end="", flush=True)
        except KeyboardInterrupt:
            print()

        logging.info("Stopping http server...")
        server.shutdown()

parser = argparse.ArgumentParser(description='Wyze product updater.')
parser.add_argument(
    '--user',
    help='User name of the associated wyze account.')
parser.add_argument(
    '--password',
    help='Password of the associated wyze account.')
parser.add_argument(
    '--token',
    default='.tokens',
    help='File for reading and storing login credential tokens.')

parser.add_argument(
    '--debug', action='store_true',
    help='Output debug informaiton.')
parser.set_defaults(debug=False)

subparsers = parser.add_subparsers(
    dest='action', required=True,
    help='Supported actions')
parser.set_defaults(action=list_devices)

SUPPORTED_MODELS = [
    'WYZEC1',           # V1
    'WYZEC1-JZ',        # V2
    'WYZECP1_JEF',      # PAN
    'WYZE_CAKP2JFUS',   # V3
    'WYZEDB3',          # Doorbell
    'WLPP1',            # Plug
    'BS_WK1',           # Sprinkler
    'WVODB1',           # Cam Outdoor Base
    'WVOD1',            # Cam Outdoor
    'GW3U',             # WyzeSense Hub
]

list_parser = subparsers.add_parser('list', help='Listing devices')
list_parser.set_defaults(action=list_devices)
list_parser.add_argument(
    '-m', '--model', dest='models', action='append', choices=SUPPORTED_MODELS,
    help='Specifying target devices by a list of device models.')

update_parser = subparsers.add_parser(
    'update', help='Updating devices')
update_parser.set_defaults(action=update_devices)
device_specifier = update_parser.add_mutually_exclusive_group()
device_specifier.add_argument(
    '-d',  '--device', dest='devices', action='append',
    help='Specifying target devices by a list of MAC addresses.')
device_specifier.add_argument(
    '-m', '--model', dest='models', action='append', choices=SUPPORTED_MODELS,
    help='Specifying target devices by a list of device models.')

update_parser.add_argument(
    '-f', '--firmware', required=True,
    help='Firmware file, required for update command.')
update_parser.add_argument(
    '-v', '--firmware-ver',
    help='Firmware version, default to 9.9.9.9')
update_parser.add_argument(
    '-s', '--ssl', action='store_true',
    help='Use HTTPS to serve the firmware data, default value: False')
update_parser.add_argument(
    '--url-host',
    help='Use specified host name in the upgrade URL, requires DNS spoofing.')

update_parser.add_argument(
    '--url-path',
    help='Use specified path in the upgrade URL, required by some devices.')

update_parser.add_argument(
    '-p', '--port', type=int,
    help='HTTP(S) serving port, default value: 80 (HTTP) or 443 (HTTPS).')
update_parser.add_argument(
    '-a', '--addr', help='HTTP(S) server binding address, default value: <auto detected>.')

args = parser.parse_args()

log_init(args.debug)

try:
    logging.info('Trying saved credentials from %s.', args.token)
    with open(args.token) as f:
        creds = json.load(f)
except OSError:
    creds = None

if not creds:
    logging.info("No saved credentials found, logging in with username/password...")
    if not args.user:
        args.user = input("Please enter the account name:")
    
    if not args.password:
        args.password = input("Please enter the password:")

    creds = wyze_login(args.user, args.password)
    try:
        with open(args.token, 'w') as f:
            json.dump(creds, f)
            logging.info('Credentials saved to %s.', args.token)
    except OSError:
        logging.error("Failed to save credentials.")

args.action(creds, args)

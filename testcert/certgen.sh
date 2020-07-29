#!/bin/sh

openssl req -x509 -new -nodes -keyout data/cert/key.pem -out data/cert/cert.pem -days 365 -subj "/C=US/ST=Oregon/L=Portland/O=Company Name/OU=Org/CN=localhost"


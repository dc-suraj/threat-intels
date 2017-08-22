#!/usr/bin/python
from bad_ips import badips
import json
s = badips()

print s.bad_ip('8.8.8.8')

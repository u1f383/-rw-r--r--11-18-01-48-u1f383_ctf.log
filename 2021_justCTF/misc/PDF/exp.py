#!/usr/bin/python3

import re
import zlib

pdf = open("challenge.pdf", "rb").read()
stream = re.compile(b'.*?FlateDecode.*?stream(.*?)endstream', re.S)

i = 0
for s in re.findall(stream,pdf):
    s = s.strip(b'\r\n')
    try:
        open(str(i), 'wb').write(zlib.decompress(s))
        i += 1
    except:
        pass
a = a.replace('\n', '').replace(' ', '')
b = bytes.fromhex(a)
open('d3', 'wb').write(b) # get jpg 

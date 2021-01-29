#!/usr/bin/python3

import subprocess
import string

table = "vwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~o"
flag = open('flag', 'r').read()

for i in range(0, len(flag), 4):
    part = flag[i:i+4]
    
    sum = 0
    for j in range(4):
        part_value = table.find(part[j])
        sum += (part_value << (6*(3-j)))

    print(sum.to_bytes(3, 'big').decode(errors='ignore'), end='')

#!/usr/bin/python3

def decode(s):
    l = len(s)+1
    s = s.encode()
    s += b'\x00'
    idx = -1
    r = []

    for i in range(l // 8):
        r.append([8, '0x' + s[i*8:(i+1)*8][::-1].hex() ])
        idx = i
    
    if idx != -1:
        idx += 1

    if l % 8 != 0:
        r.append([l%8, '0x' + s[idx*8:][::-1].hex()])

    return r

while True:
    s = input("> ")

    print(decode(s))

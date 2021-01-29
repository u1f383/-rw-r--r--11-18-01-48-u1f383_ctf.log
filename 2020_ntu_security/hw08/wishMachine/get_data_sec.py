#!/usr/bin/python3

with open('./patch_binary', 'rb') as f:
    f.seek(0xD5100) # 0x20 is padding from .data base
    data_sec = f.read(0x1cb810 - 0x20) # size of .data
    open('data_sec', 'wb').write(data_sec)


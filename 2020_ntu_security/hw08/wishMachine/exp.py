#!/usr/bin/python3

from pwn import *
import string

datas = open('./data_sec', 'rb').read()
serials_char = []

for i in string.ascii_uppercase:
    serials_char.append(ord(i))

for i in string.digits:
    serials_char.append(ord(i))

def fib(n):
    a, b, c = 0, 1, 0

    for i in range(n+1):
        c = a+b
        a = b
        b = c

    return a

def get_fb_idx(fb_value): # 0x4011d6
    if fb_value == 0:
        return 0
    
    for i in serials_char:
        if (fib(i) & 0xffffffff) == (fb_value & 0xffffffff):
            return i

    return 0

def op13(value): # 0x40102d
    n = (value // 13)*2
    n += 1 if value % 13 == 11 else 0

    return n

def wtf(value): # 0x401138
    v1 = 0xFAC0B00C - value
    a, b = 120, 30600

    n = (v1 // (a+b)) * 2
    n += 1 if v1 % (a+b) == 30600 else 0

    return n

def xfunc(value): # 0x4010c8
    return 0x52756279 ^ value

def x135(value): # 0x400fbe
    return value // 135

"""
struct {
	int base; // 0-3
	int no[3]; // 4-15
	int offset; // 16-19
	int pos; // 20-23
	int num; // 24-27
	int fb_value1; // 28-31
	int fb_value2; // 32-35
	int no; // 36-39
}
"""
def extract(data):
    base = u32(data[:4])
    offset = u32(data[16:20])
    pos = u32(data[20:24])
    num = u32(data[24:28])
    value1 = u32(data[28:32])
    value2 = u32(data[32:36])

    return {"base":base, "offset":offset, "pos": pos, "num":num, "value1":value1, "value2":value2}


arr_size = len(datas)
arr_len = 40
arr_block_num = arr_size // arr_len
i = 0

f = open('serial.txt', 'w')

for j in range(1000):
    serial = [0]*70
    while True:
        data = extract( datas[i*arr_len : (i+1)*arr_len] )

        if data['base'] + data['offset'] == 0x40102d: # op13
            serial[ data['pos'] ] = op13(data['value1'])

            if data['num'] == 2:
                serial[ data['pos']+1 ] = op13(data['value2'])

        elif data['base'] + data['offset'] == 0x4011d6: # fabonacci
            serial[ data['pos'] ] = get_fb_idx(data['value1'])

            if data['num'] == 2:
                serial[ data['pos']+1 ] = get_fb_idx(data['value2'])
        elif data['base'] + data['offset'] == 0x401138: # wtf
            serial[ data['pos'] ] = wtf(data['value1'])

            if data['num'] == 2:
                serial[ data['pos']+1 ] = wtf(data['value2'])
        elif data['base'] + data['offset'] == 0x4010c8: # xfunc
            serial[ data['pos'] ] = xfunc(data['value1'])

            if data['num'] == 2:
                serial[ data['pos']+1 ] = xfunc(data['value2'])
        elif data['base'] + data['offset'] == 0x400fbe: # x135
            serial[ data['pos'] ] = x135(data['value1'])

            if data['num'] == 2:
                serial[ data['pos']+1 ] = x135(data['value2'])
        else:
            print(hex(data['base'] + data['offset']))
            print("unknown")
            exit(1)

        i += 1

        if 0 not in serial:
            #print(''.join(list(map(chr, serial))))
            f.write(''.join(list(map(chr, serial))) + '\n' )
            break

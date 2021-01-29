#!/usr/bin/python3

from pwn import *
import subprocess


key1 = open('export_results.txt', 'rb').read()
key2 = [8, 1, 2, 7, 5, 3, 6, 4, 9, 9, 4, 3, 6, 8, 2, 1, 7, 5, 6, 7, 5, 4, 9, 1, 2, 8, 3, 1, 5, 4, 2, 3, 7, 8, 9, 6, 3, 6, 9, 8, 4, 5, 7, 2, 1, 2, 8, 7, 1, 6, 9, 5, 3, 4, 5, 2, 1, 9, 7, 4, 3, 6, 8, 4, 3, 8, 5, 2, 6, 9, 1, 7, 7, 9, 6, 3, 1, 8, 4, 5, 2]
printable_range = [i for i in range(32, 127)]

def run(flag):
    #p = subprocess.Popen(['./test'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    open('result', 'wb').write(flag)
    p = subprocess.Popen(['cat', 'result'])
    #out, err = p.communicate()
    #print(out)

"""
a = const
b = 9x9
c = input
"""
def result(a, b, c, size):
    s = 0
    flag = b''
    for i in range(size): # 3160, 6015
        qq = a[i] ^ b[ i % len(b) ] ^ c[ i % len(c) ]
        s += qq
        flag += bytes([qq])

    return s, flag

def check_printable(a, b):
    if a^b in printable_range:
        return True
    return False


def test():
    qq = b''
    for i in range(1):
        key3 = bytes([32])
        res, con = result(key1, key2, key3, 6015)
        qq += con
    run(qq)

test()
exit(1)

key3 = b'\x00'
res, con = result(key1, key2, key3, 6015) # get first xor result
con += b'\x00'

block_size = 32
block_len = 6015 // 32


def get_key_range():
    xor_dict = {}
    
    for i in range(32):
        xor_dict[ str(i) ] = []
    
    for curr in range(32):

        for key in printable_range:

            can_print = True

            for block in range(block_size): # check if all block xor result is printable

                if not check_printable( key , con[ block*block_size + curr ] ):
                    can_print = False
                    break

            if can_print:
                xor_dict[ str(curr) ].append( chr(key) )

    return xor_dict

xor_dict = get_key_range()


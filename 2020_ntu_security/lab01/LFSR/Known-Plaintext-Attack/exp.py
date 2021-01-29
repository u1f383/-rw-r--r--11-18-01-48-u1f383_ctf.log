import random
from functools import reduce

#from sage.all import *

class LFSR:
    def __init__(self, init, feedback):
        self.state = init
        self.feedback = feedback
    @classmethod
    def random(cls, size):
        init = [random.choice([0, 1]) for i in range(size)]
        feedback = [random.choice([0, 1]) for i in range(size)]
        return cls(init, feedback)
    def getbit(self):
        nextbit = reduce(lambda x, y: x ^ y, [i & j for i, j in zip(self.state, self.feedback)])
        self.state = self.state[1:] + [nextbit]
        return nextbit
    def getbyte(self):
        b = 0
        for i in range(8):
            b = (b << 1) + self.getbit()
        return bytes([b])

def xor(a, b):
    return bytes([i ^ j for i, j in zip(a, b)])

def bytes2bits(x):
    return [int(i) for i in f'{int.from_bytes(x, "big"):0{len(x) * 8}b}']

"""
FLAG = open('./flag', 'rb').read()
assert FLAG.startswith(b'CTF{')

lfsr = LFSR.random(16)
key = b''.join([lfsr.getbyte() for i in range(len(FLAG))]) # use lfsr to generate key which len is 9
print(f'enc = {xor(FLAG, key).hex()}')
"""
lfsr = LFSR.random(16)
key = b''.join([lfsr.getbyte() for i in range(9)]) # use lfsr to generate key which len is 9
print(bytes2bits(key))
print('\n\n')
print(lfsr.state)
exit(1)

enc = bytes.fromhex('d0aa72cef8dab5baac') # flag start with 'CTF{', and len(flag) == 9
stream = xor(enc[:4], b'CTF{') # part of key (s0 ~ s32)
s = [GF(2)(i) for i in bytes2bits(stream)] # transfer to bit, and then transfer to GF to limit value range (0~1)
# because feedback size is 16, we can use 32 bit (16*2) S to find the feedback

feedback = ([0]*16 + berlekamp_massey(s).list()[:-1])[-16:] # less than 16, filled with 0
feedback = list(map(int, feedback))
print("stream:   ")
print(bytes2bits(stream))

# get plain
lfsr = LFSR(bytes2bits(stream)[16:], feedback) # let init be stream[16:], and it will generate the rest of key stream (5 bytes)
key = b''.join([lfsr.getbyte() for _ in range(5)])
plain = xor(enc[4:], key)
print(plain)

"""
Important!!
Initial value will not be part of key.
"""

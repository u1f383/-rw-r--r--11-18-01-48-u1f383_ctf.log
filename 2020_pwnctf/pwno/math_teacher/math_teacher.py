#!/usr/bin/python3

from pwn import *
from z3 import *
import operator

r = remote('140.110.112.77', 9003)

ops = {
    "+": operator.add,
    "-": operator.sub,
    "*": operator.mul,
}

context.log_level='debug'
while True:
    l1 = r.recvline()[:-1].decode().split(' ')
    l2 = r.recvline()[:-1].decode().split(' ')
    x = Int('x')
    y = Int('y')
    s = Solver()
    # [b'9', b'*', b'x', b'+', b'10', b'*', b'y', b'=', b'648'] [b'10', b'*', b'x', b'+', b'7', b'*', b'y', b'=', b'683']
    s.add(ops[ l1[3] ]( ops[ l1[1] ](int(l1[0]) , x) , ops[ l1[5] ](int(l1[4]) , y) ) == int(l1[8]))
    s.add(ops[ l2[3] ]( ops[ l2[1] ](int(l2[0]) , x) , ops[ l2[5] ](int(l2[4]) , y) ) == int(l2[8]))

    s.check()
    res = s.model()
    x = res[x].as_long()
    y = res[y].as_long()
    r.recv()
    r.sendline(str(x))
    r.recv()
    r.sendline(str(y))
    
r.interactive()

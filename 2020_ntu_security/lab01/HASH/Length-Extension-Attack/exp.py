#!/usr/bin/python3
import hashpumpy
import base64
from pwn import *

salt = 'THISISJUSTSALTNOTSWEETHAHAHA'
r = remote('127.0.0.1', 20000)

r.recvuntil('your token: ')
token = base64.b64decode(r.recvline().strip())
r.recvuntil('your authentication code: ')
auth = r.recvline().strip()
# hashpump(hexdigest, original_data, data_to_add, key_length) -> (digest, message)
new_auth, new_token = hashpumpy.hashpump(
    auth,
    token,
    'user=admin',
    len(salt),
)
print("old")
print("auth:  ", end='')
print(auth)
print("token:  ", end='')
print(token)

print("\nnew")
print("auth:  ", end='')
print(new_auth)
print("token:  ", end='')
print(new_token)

r.sendline(base64.b64encode(new_token))
r.sendline(new_auth)
print(r.recvline())
print(r.recvline())
print(r.recvline())

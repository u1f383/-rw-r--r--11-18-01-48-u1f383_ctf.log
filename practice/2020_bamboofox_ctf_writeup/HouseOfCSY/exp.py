#!/usr/bin/python3

from pwn import *

HOST = 'localhost'
PORT = '54321'

def menu(i):
    r.sendafter('Choose> ', str(i) + '\x00')

def create(r, name):
    menu(1)
    r.sendafter('Room name: ', name) # most 0x1f
    r.recvuntil('Room created!!! Room id: ')
    room_id = int(r.recvline()[:-1])

    return room_id

def show(r, room_id):
    memu(2)
    r.sendafter('Input index: ', str(room_id) + '\x00') # cannot larger than 4 or freed
    r.recvuntil('Room ')
    room_name = r.recvline()[:-1]
    r.recvuntil('Users in the room:')

def enter(r, room_id, name):
    menu(3)
    r.sendafter('Which room do you want to enter: ', str(room_id) + '\x00')
    r.sendafter("What's your name: ", name)

def remove(r, room_id):
    menu(4)
    r.sendafter('Which room do you want to destruct: ', str(room_id) + '\x00')

rs = []
for i in range(5):
    rs.append( remote(HOST, PORT) )


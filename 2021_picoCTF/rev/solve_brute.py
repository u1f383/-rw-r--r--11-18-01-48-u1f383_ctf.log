def swap(src, l, idx):
    for i in range(0, 0xffff, idx):
        r = l - idx + 1
        if i >= r:
            break
        tmp = src[i]
        src[i] = src[i+idx-1]
        src[i+idx-1] = tmp

def rev_swap(src, l, idx):
    r = l - idx + 1
    q = 0

    while q+idx < r:
        q += idx

    for i in range(q, -1, -idx):
        tmp = src[i]
        src[i] = src[i+idx-1]
        src[i+idx-1] = tmp

def do_enc(myinput):
    for i in range(0xABCF00D, 0xDEADBEEF, 0x1FAB4D):
        a = []
        a.append(i >> 0x18)
        a.append((i >> 0x10) & 0xff)
        a.append((i >> 0x8) & 0xff)
        a.append(i & 0xff)

        newinput = b''
        for j in range(0, 0x20):
            newinput += bytes([myinput[j] ^ a[j & 3]])
        
        myinput = newinput

    return bytearray(myinput)


# myinput = b'123456\n'.ljust(0x20, b'\x00')
myinput = open('flag', 'rb').read() # len = 0x1e
myinput = myinput.ljust(0x20, b'\x00')
src = bytearray(myinput)

# for i in range(0x1e-1, 0, -1):
#     swap(src, 0x1e, i)

src = bytearray(myinput)
for i in range(0x1d, 0, -1):
    rev_swap(src, 0x1e, i)

myinput = bytes(src)
src = do_enc(myinput)

print(bytes(src))



# 0x1e - 3 + 1
# 0x1c
# i = 0, 3, 6, .., 0x1b
# tmp = s[i]
# s[i] = src[i+3-1]
# src[i+3-1] = tmp

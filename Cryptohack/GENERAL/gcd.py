#!/usr/bin/python3

def gcd(a, b):
    if b == 0:
        return a
    return gcd(b, a%b)

a = int(input('a = '))
b = int(input('b = '))

print(f"gcd: {gcd(a, b)}")

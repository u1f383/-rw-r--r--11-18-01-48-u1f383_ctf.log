"""
https://math.stackexchange.com/questions/1952453/finding-an-integer-x-and-a-3-digit-prime-p-that-solves-the-problem/1952471

mod 底下原來也能像一般方程式做加減乘除
x^n = 588 mod p
x^(n+1) = 665 mod p
=> 558x = 665 mod p
=> 665x = 216 mod p
以此類推
for x^(n+i) = ai mod p, a(i-1)*x = ai for i >= 1

"""
ints = [588, 665, 216, 113, 642, 4, 836, 114, 851, 492, 819, 237]
"""
1000 > p > 836
gcd(4,836) == 4
gcd(642,4) == 2
=> x = 209 mod p
=> 321x = 2 mod p

321*209 = 2 mod p
p | 321*209 - 2
"""

for i in range(837, 1000):
    if (321*209-2) % i == 0:
        print(i)
# or 321*209-2 == 67087 == 73 * 919
# p = 919
# x = 209
"""
http://gotonsb-numbertheory.blogspot.com/2014/04/quadratic-residues.html

Quadratic Residues：
定義：
- 任意非零平方整數除以某個數後可能的餘數即為「二次剩餘」，為一集合
- For x, m ≠ 0, a is a quadratic residue mod m if x^2 = a (mod m)

如何快速判斷任意 a 是否為 mod p 的二次剩餘 for (a,p) = 1，p 為 prime？  A: Euler's Criterion
- 如果 a 為二次剩餘， a^(p-1 / 2) = 1 mod p
- 如果 a 為二次非剩餘， a^(p-1 / 2) = -1 mod p

但是如果 p 很大，a^(p-1 / 2) 會非常大

Legendre Symbol (勒讓得符號)：
(a/p) =def= a(p−1 / 2)(mod p) 
"""
p = 29
ints = {14, 6, 11}

x_set = { f"{x}": (x**2 % 29) for x in range(29-1) }
r = dict(sorted(x_set.items(), key=lambda item: item[1]))
r = dict(filter(lambda item: item[1] in ints, r.items()))

print(r)
"""
https://zh.wikipedia.org/wiki/%E4%B8%AD%E5%9B%BD%E5%89%A9%E4%BD%99%E5%AE%9A%E7%90%86

中國餘數可以找出同餘方程式 (linear congruences) 中的唯一解

同餘方程式如下，給一整數在 mod nn 底下的值 an，求得此整數的值
x ≡ a1 mod n1
x ≡ a2 mod n2
...
x ≡ an mod nn
前提為 an nn 彼此 coprime

P.S. x ≡ a mod p 可以寫成 x = a + k*p for 任意 k
"""

"""
Question
x ≡ 2 mod 5
x ≡ 3 mod 11
x ≡ 5 mod 17

find integer a such that x ≡ a mod 935
"""

M = 5*11*17
M1 = M // 5
M2 = M // 11
M3 = M // 17

# https://doc.sagemath.org/html/en/tutorial/tour_numtheory.html
# 1
t1 = inverse_mod(M1, 5)
t2 = inverse_mod(M2, 11)
t3 = inverse_mod(M3, 17)
# 2
"""
_, x, y = xgcd(M1, 5)
t1 = mod(x, 5)
...
"""
S = M1*t1*2 + M2*t2*3 + M3*t3*5
for i in range(3):
    print(S + M*i, (S + M*i)%935)
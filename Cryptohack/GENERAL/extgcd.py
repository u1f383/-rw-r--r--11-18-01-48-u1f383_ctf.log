#!/usr/bin/python3

# find x, y for ax + by = gcd(a,b)
# Bézout's lemma
s0, s1 = 1, 0
t0, t1 = 0, 1
def extgcd(r0, r1, s0, s1, t0, t1):
    if r1 == 0:
        return [r0, r1, s0, s1, t0, t1]
    q = r0 // r1
    r2 = r0 - r1*q
    s2 = s0 - s1*q
    t2 = t0 - t1*q
    
    return extgcd(r1, r2, s1, s2, t1, t2)

r0 = int(input('r0 = '))
r1 = int(input('r1 = '))

res = extgcd(r0, r1, s0, s1, t0, t1)
r, _, s, _, t, _ = (*res, )
print("{}*{} + {}*{} = {}".format(s, r0, t, r1, r))

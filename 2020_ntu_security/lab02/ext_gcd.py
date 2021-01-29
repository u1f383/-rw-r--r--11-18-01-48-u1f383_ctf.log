def ext_gcd(a, b):
    s0, t1 = 1, 1
    s1, t0 = 0, 0

    while b:
        q = a // b
        s0, s1 = s1, s0 - q*s1
        t0, t1 = t1, t0 - q*t1
        a, b = b, a%b

    return s0, t0, a

x, y = 240, 46
a, b, result = ext_gcd(x, y)

print(f"{a}*{x}+{b}*{y}", '=', result)
assert(a*x+b*y == result)
"""
給 a basis v1, v2, ..., vn ∈ V，用 Gram Schmidt Algorithm 求得 an orthogonal basis u1, u2, ..., un ∈ V

Pseudo code
u1 = v1
Loop i = 2,3...,n
   Compute μij = vi ∙ uj / ||uj||2, 1 ≤ j < i.
   Set ui = vi - μij * uj (Sum over j for 1 ≤ j < i)
End Loop
https://ccjou.wordpress.com/2010/04/22/gram-schmidt-%E6%AD%A3%E4%BA%A4%E5%8C%96%E8%88%87-qr-%E5%88%86%E8%A7%A3/
"""

v1 = Matrix([4,1,3,-1]).transpose()
v2 = Matrix([2,1,-3,4]).transpose()
v3 = Matrix([1,0,-2,7]).transpose()
v4 = Matrix([6,2,9,-5]).transpose()

V = [v2 ,v3, v4]
U = []

def get_sum(U):
    sum_u = Matrix([[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]).transpose()

    for u in U:
        sum_u += (u*u.transpose() / (u.transpose()*u)[0,0])

    return sum_u

U.append(v1)
for v in V:
    u = v - get_sum(U)*v
    U.append(u)

print(U[3][1]) # 要四捨五入
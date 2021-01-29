"""
給一堆 vector v1, v2, ..., vk ∈ V，滿足：
a1*v1 + a2*v2 + ... + ak*vk = 0 只有唯一解 a1 = a2 = ... = ak = 0
就稱做這些 vector 彼此線性獨立

||v|| 為 size of vector，而 ||v||^2 = v ∙ v

如果 vector basic v1, v2, ..., vn ∈ V 為 orthogonal (正交)，則滿足 vi ∙ vj = 0, 任意 i,j for i ≠ j (orthogonal basis)
如果 vector basic 為 orthonormal，則滿足 orthogonal and ||vi|| = 1, for all i
"""

v = vector([4, 6, 2, 5])

print(v.norm())
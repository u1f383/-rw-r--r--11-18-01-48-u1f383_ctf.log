"""
Help：
https://www.cryptool.org/assets/img/ctp/documents/CTB-Chapter_Lattice-Introduction_en.pdf
http://ohmycakelus.blogspot.com/2012/02/vector-spaces.html

Vector operation
"""

v = vector([2,6,3])
w = vector([1,0,0])
u = vector([7,7,2])

print(3*(2*v - w).inner_product(2*u))
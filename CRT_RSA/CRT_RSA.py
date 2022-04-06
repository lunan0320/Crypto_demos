import time
from gmpy2 import invert
start=time.time()
print("普通RSA解密结果：",pow(152702,2015347)%3026533)
end=time.time()
print("耗时：",end-start,"s")
def CRT_RSA(c,p,q,d,n):
    c1=c%p
    c2=c%q
    r1=d%(p-1)
    r2=d%(q-1)
    m1=pow(c1,r1)%p
    m2=pow(c2,r2)%q
    p_1=invert(p,q)
    q_1=invert(q,p)
    m=(m2*p*p_1+m1*q*q_1)%n
    return m
start=time.time()
m=CRT_RSA(152702,1511,2003,2015347,3026533)
end=time.time()
print("CRT_RSA解密结果：",m)
print("耗时：",end-start,"s")
import random
import math

def prime():
    prime = 0
    while prime == 0:
        num = random.randint(99,999)

        for i in range(2, (num//2)): 
     
            if (num % i) == 0:
                 prime = 0
                 break
        else:
            prime = num 
            return prime
            break 

def gcd(a,b):
    while b != 0:
        a, b = b, a % b
    return a

def Roots(modulo):
    roots = []
    required_set = set(num for num in range (1, modulo) if gcd(num, modulo) == 1)
    
    for g in range(1, modulo):
        actual_set = set(pow(g, powers) % modulo for powers in range (1, modulo))
        if required_set == actual_set:
            roots.append(g)
            if len(roots)>3:
                break
    return roots

def primeRoot():
    while True:
        q = prime()
        primitive_roots = Roots(q)
        if len(primitive_roots) == 0:
            continue
        else:
            break
    return(q,random.choice(list(primitive_roots)))

def Xab(q,alpha):
    x = random.randint(1,q)
    y = pow(alpha,x,q)
    return x,y


def key(y,x,q):
    k = pow(y,x,q)
    return k
    


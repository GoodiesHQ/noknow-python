# coding: utf-8
from math import sqrt, ceil


def prime_factorization(p: int):
    """Find all prime factors of the number p"""
    d, factors = 2, []
    while d**2 <= p:
        while (p % d) == 0:
            factors.append(d)
            p //= d
        d += 1
    return factors + ([p] if p > 1 else [])


def count_occurances(factors):
    """Count occurances of each prime factor"""
    return [[x, factors.count(x)] for x in set(factors)]

def egcd(a, b):
    """Extended Euclidian algorithm for finding GCD"""
    a2, a1 = 1, 0
    b2, b1 = 0, 1
    while b:
        q, r = divmod(a, b)
        a1, a2 = a2 - q * a1, a1
        b1, b2 = b2 - q * b1, b1
        a, b = b, r
    return a, a2, b2

def mod_inv(b, n):
    """Return x s.t. x ≡ a^(-1) (mod n)"""
    g, x, _ = egcd(b, n)
    if g == 1:
        return x % n

def chinese_remainder(pairs):
    """Chinese remainder theorem for solving a system of congruences"""
    N, X = pairs[0][1], 0
    for ni in pairs[1:]:
        N *= ni[1]
    for (ai, ni) in pairs:
        mi = (N // ni)
        X += mi * ai * egcd(mi, ni)[1]
    return X % N

def shanks_algorithm(alpha, beta, n):
    """Return x s.t. beta ≡ alpha^(x) (mod n)"""
    m = int(ceil(sqrt(n - 1)))
    a = pow(alpha, m, n)
    b = egcd(alpha, n)[1]
    L1 = [(j, pow(a, j, n)) for j in range(0, m)]
    L2 = [(i, beta * (b ** i) % n) for i in range(0, m)]
    L1.sort(key = lambda tup: tup[1])
    L2.sort(key = lambda tup: tup[1])
    i, j, Found = 0, 0, False
    while (not Found) and (i < m) and (j < m):
        if L1[j][1] == L2[i][1]:
            return m * L1[j][0] + L2[i][0] % n
        elif abs(L1[j][1]) > abs(L2[i][1]):
            i = i + 1
        else:
            j = j + 1

def congruence_pair(g, h, p, q, e, e1, e2):
    """Return pair (x, q ** e) which represents one congruence"""
    alphaInverse = mod_inv(e1, p)
    x = 0 # x = x_{0} + x_{1} * q + x_{2} * q^{2} + ... + x_{e - 1} * q^{e - 1}
    for i in range(1, e + 1):
        a = pow(e1, pow(q, e - 1), p)
        b = pow(e2 * pow(alphaInverse, x), pow(q, (e - i), p), p)
        x += shanks_algorithm(a, b, p) * pow(q, (i - 1))
    return (x, pow(q, e))

def PrintFormated(arg1, arg2, arg3, arg4, arg5):
    pass
    # print(" {:3s} | {:3s} | {:13s} | {:13s} | {:45s}".format(str(arg1), str(arg2), str(arg3), str(arg4), str(arg5)))
    # print("-"*90)

def pohling_hellman(g, h, p):
    """Main function of Pohling-Hellman's algorithm"""

    occurances = count_occurances(prime_factorization(p - 1))
    CongruenceList = []

    # print("\n")
    # print("-"*90)
    # print(" Solving %d ≡ %d^x (mod %d)" % (g, h, p))
    # print("-"*90)
    PrintFormated("q", "e", "g^((p-1)/q^e)", "h^((p-1)/q^e)", "Solve (g^((p-1)/q^e))^x = h^((p-1)/q^e) for x")

    for o in occurances:
        # e1 = int(h ** ((p - 1) / (o[0] ** o[1]))) % p # e1 = g^((p-1)/q^e)
        # e2 = int(g ** ((p - 1) / (o[0] ** o[1]))) % p # e2 = h^((p-1)/q^e)
        z = (p-1)//pow(o[0], o[1])
        e1 = pow(h, z, p)
        e2 = pow(g, z, p)
        # Add new congruence
        CongruenceList.append(congruence_pair(g, h, p, o[0], o[1], e1, e2))
        c = CongruenceList[-1]
        e3, e4 = c[0] % c[1], c[1]
        PrintFormated(o[0], o[1], e1, e2, "x ≡ %2d (mod %2d)" % (e3, e4))

    # Solve the system of congruences
    solution = chinese_remainder(CongruenceList)
    # print(" Solution x = %d" % solution)
    return solution

if __name__ == '__main__':

    print("\nPress CTRL + C to exit\n")
    print("="*90)
    print("Pohling-Hellman's algorithm for descrete logartihm")
    print("Formula : h ≡ g^x (mod p)")
    print("="*90)
    print("\n")

    # TEST EXAMPLES(h, g, p)         SOLUTIONS
    #PohlingHellman(18, 2, 29)          11
    #PohlingHellman(166, 7, 433)        47
    #PohlingHellman(7531, 6, 8101)      6689
    #PohlingHellman(525, 3, 809)        309
    #PohlingHellman(12, 7, 41)          13
    #PohlingHellman(70, 2, 131)         13
    #PohlingHellman(525, 2, 809)        no solution
    #PohlingHellman(525, -2, 131)       0

    h, g, p = 40086, 48398, 60757
    # h, g, p = 18, 2, 29
    try:
        print("Solution =", pohling_hellman(h, g, p))
    except TypeError:
        print(" The congruence %d ≡ %d^x (mod %d) has no solution " % (h, g, p))
        print("-" * 90)
        print("\n")

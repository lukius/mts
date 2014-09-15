class GCD(object):
    
    def value(self, a, b):
        return ExtendedGCD().value(a, b)[2]


class ExtendedGCD(object):
    
    def value(self, a, b):
        # Compute x and y such that
        # a * x + b * y = GCD(a, b)
        # Based on the extended Euclidean algorithm.
        s = 0
        x = 1
        t = 1
        y = 0
        r = b
        gcd = a
        
        while r != 0:
            q = gcd/r
            gcd, r = r, gcd - q*r
            x, s = s, x - q*s
            y, t = t, y - q*t
            
        return x, y, gcd
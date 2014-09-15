from common.math.gcd import ExtendedGCD


class ModularInverse(object):
    
    def __init__(self, modulus):
        self.modulus = modulus
        
    def value(self, a):
        x, _, gcd = ExtendedGCD().value(a, self.modulus)
        if gcd != 1:
            # a and the modulus have to be coprime for the modular inverse
            # to exist. If they are not, just return None.
            return None
        return x % self.modulus
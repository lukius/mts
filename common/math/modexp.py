class ModularExp(object):
    
    def __init__(self, modulus):
        self.modulus = modulus
        
    def value(self, base, exponent):
        result = 1
        base = base % self.modulus
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result*base) % self.modulus
            exponent >>= 1
            base = (base*base) % self.modulus
        return result
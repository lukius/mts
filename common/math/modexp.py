class ModularExp(object):
    
    def __init__(self, base, exponent):
        self.base = base
        self.exponent = exponent
        
    def value(self, modulus):
        result = 1
        base = self.base % modulus
        exponent = self.exponent
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result*base) % modulus
            exponent >>= 1
            base = (base*base) % modulus
        return result
import random

from common.math.modexp import ModularExp


class DiffieHellman(object):
    
    MAX_INT = 2**64 - 1
    
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.exp = self._choose_secret_exponent()
        self.public_key = self._compute_public_key()
        
    def _choose_secret_exponent(self):
        return random.randint(1, self.MAX_INT)
    
    def _compute_public_key(self):
        return ModularExp(self.g, self.exp).value(self.p)
        
    def get_public_key(self):
        return self.public_key
    
    def get_secret_from(self, key):
        return ModularExp(key, self.exp).value(self.p)
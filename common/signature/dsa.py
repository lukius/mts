import random

from Crypto.Util import number

from common.hash.sha256 import SHA256
from common.math.invmod import ModularInverse
from common.math.modexp import ModularExp
from common.math.prime import RandPrime
from common.signature import DigitalSignatureScheme


class DSA(DigitalSignatureScheme):
    
    # Based on Wikipedia pseudocode.
    
    def __init__(self, hash_function=SHA256, parameters=None):
        DigitalSignatureScheme.__init__(self)
        self.hash_function = hash_function()
        self._init_params_from(parameters)
        self.modexp_p = ModularExp(self.p)
        self._init_keys()
        
    def _init_params_from(self, parameters):
        if parameters is None:
            self.p, self.q, self.g = DSAParameterGenerator().generate()
        else:
            self.p, self.q, self.g = parameters
        
    def _init_keys(self):
        self.x = random.randint(1, self.q-1)
        self.y = self.modexp_p.value(self.g, self.x)
        self.public_key = (self.p, self.q, self.g, self.y)
        
    def sign(self, message):
        h = self.hash_function.int_hash(message)
        while True:
            k = random.randint(1, self.q-1)
            r = self.modexp_p.value(self.g, k) % self.q
            if r == 0:
                continue
            k_inv = ModularInverse(self.q).value(k)
            s = k_inv*(h + self.x*r) % self.q
            if s != 0:
                break
        return r, s
    
    def verify(self, message, signature):
        r, s = signature
        if (r <= 0 or r >= self.q) or (s <= 0 or s >= self.q):
            return False
        h = self.hash_function.int_hash(message)
        w = ModularInverse(self.q).value(s)
        u1 = (h*w) % self.q
        u2 = (r*w) % self.q
        g_u1 = self.modexp_p.value(self.g, u1)
        y_u2 = self.modexp_p.value(self.y, u2)
        v_mod_p = (g_u1*y_u2) % self.p
        v = v_mod_p % self.q
        return r == v
    
    
class DSAParameterGenerator(object):
    
    DEFAULT_L = 2048
    DEFAULT_N = 256
    DEFAULT_H = 2
    
    def __init__(self, L=None, N=None):
        self.prime_generator = RandPrime()
        self.L = self.DEFAULT_L if L is None else L
        self.N = self.DEFAULT_N if N is None else N
        
    def _choose_p_from(self, q):
        i = 2
        while True:
            p = i*q + 1
            # TODO: implement Miller-Rabin
            if number.isPrime(p):
                break
            i += 1
        return p
                
    def _choose_g_from(self, p, q):
        h = self.DEFAULT_H
        while True:
            g = ModularExp(p).value(h, (p-1)/q)
            if g != 1:
                break
        return g
    
    def generate(self):
        q = self.prime_generator.value(self.N)
        p = self._choose_p_from(q)
        g = self._choose_g_from(p, q)
        return p, q, g
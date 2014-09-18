from common.challenge import MatasanoChallenge
from common.math.invmod import ModularInverse
from common.math.modexp import ModularExp
from common.signature.dsa import DSA, DSAParameterGenerator


class DSAMagicSignature(object):
    
    def value(self, dsa):
        # z should be chosen s.t. it has modular inverse mod q. 
        # A small prime will be enough.
        z = 11
        p, q, _, y = dsa.get_public_key()
        
        r = ModularExp(p).value(y, z) % q
        z_inv = ModularInverse(q).value(z)
        s = (r*z_inv) % q
        return r, s


class Set6Challenge5(MatasanoChallenge):
    
    STRING1 = 'Hello, world'
    STRING2 = 'Goodbye, world'

    def validate(self):
        p, q, _ = DSAParameterGenerator().generate()
        # using g = 1 is the same as using g = p+1. For any k, using the
        # Binomial Theorem,
        # (p+1)**k = SUM_0_k C(k,i) * p**i * 1**(k-i)
        #          = C(k,0) * 1**k + SUM_1_k C(k,i) * p**i * 1**(k-i)
        #          = 1 mod p
        dsa = DSA(parameters=(p, q, 1))
        signature = DSAMagicSignature().value(dsa)
        
        return dsa.verify(self.STRING1, signature) and\
               dsa.verify(self.STRING2, signature)
from common.challenge import MatasanoChallenge
from common.ciphers.pubkey.rsa import RSA
from common.math.modexp import ModularExp
from common.tools.base64 import Base64Decoder
from common.tools.converters import BytesToInt, IntToBytes


class RSAParityOracleDecrypter(object):
    
    def __init__(self, oracle):
        self.oracle = oracle
        self.e, self.n = oracle.get_public_key()
        
    def _multiply(self, a, b):
        return (a*b) % self.n
        
    def decrypt(self, ciphertext):
        int_ciphertext = BytesToInt(ciphertext).value()
        # Invariant: the plaintext is in the interval
        # [lower_limit, upper_limit]
        lower_limit = 0
        upper_limit = self.n-1
        two_i = two = ModularExp(self.n).value(2, self.e)
        
        while lower_limit < upper_limit:
            mid = (lower_limit+upper_limit)/2
            mid_ciphertext = ModularExp(self.n).value(mid, self.e)
            mid_ciphertext = self._multiply(mid_ciphertext, two_i)
            target_ciphertext = self._multiply(int_ciphertext, two_i)
            if self.oracle.is_plaintext_even(target_ciphertext):
                upper_limit = mid
                # Adjust new upper limit if it violates the invariant.
                if not self.oracle.is_plaintext_even(mid_ciphertext):
                    upper_limit -= 1
            else:
                lower_limit = mid
                # Same as before.
                if self.oracle.is_plaintext_even(mid_ciphertext):
                    lower_limit += 1
            two_i = (two_i*two) % self.n
            
        return IntToBytes(lower_limit).value()


class RSAParityOracle(object):
    
    def __init__(self, rsa):
        self.rsa = rsa
        
    def get_public_key(self):
        return self.rsa.get_public_key()
    
    def is_plaintext_even(self, ciphertext):
        int_plaintext = self.rsa.int_decrypt(ciphertext)
        return int_plaintext % 2 == 0


class Set6Challenge6(MatasanoChallenge):
    
    STRING = 'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRo'+\
             'IHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='

    def __init__(self):
        MatasanoChallenge.__init__(self)
        self.plaintext = Base64Decoder().decode(self.STRING)

    def expected_value(self):
        return self.plaintext

    def value(self):
        rsa = RSA()
        oracle = RSAParityOracle(rsa)
        ciphertext = rsa.encrypt(self.plaintext)
        return RSAParityOracleDecrypter(oracle).decrypt(ciphertext)
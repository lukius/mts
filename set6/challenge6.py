from common.challenge import MatasanoChallenge
from common.ciphers.pubkey.rsa import RSA
from common.math.modexp import ModularExp
from common.tools.base64 import Base64Decoder
from common.tools.converters import BytesToInt, IntToBytes


class RSAParityOracleDecrypter(object):
    
    def __init__(self, oracle):
        self.oracle = oracle
        self.e, self.n = oracle.get_public_key()
        
    def decrypt(self, ciphertext):
        int_ciphertext = BytesToInt(ciphertext).value()
        lower_limit = 0
        upper_limit = self.n-1
        two = ModularExp(self.n).value(2, self.e)
        while lower_limit < upper_limit:
            mid = (lower_limit+upper_limit)/2
            int_ciphertext = (int_ciphertext*two) % self.n
            if self.oracle.is_plaintext_even(int_ciphertext):
                upper_limit = mid
            else:
                lower_limit = mid+1
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
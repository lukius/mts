from common.attacks.pkcs1_5 import PKCS1_5PaddingOracleAttack,\
                                   PKCS1_5PaddingOracle
from common.challenge import MatasanoChallenge
from common.ciphers.pubkey.rsa import RSA
from common.tools.padders import PKCS1_5Padder


class Set6Challenge8(MatasanoChallenge):
    
    STRING = 'Pochoclin!'
    
    def __init__(self):
        self.padded_string = PKCS1_5Padder(self.STRING).value(size=32)
    
    def expected_value(self):
        return self.padded_string

    def value(self):
        rsa = RSA(bits=768)
        oracle = PKCS1_5PaddingOracle(rsa)
        ciphertext = rsa.encrypt(self.padded_string)
        return PKCS1_5PaddingOracleAttack(oracle).decrypt(ciphertext)
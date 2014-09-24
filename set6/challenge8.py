from common.attacks.pkcs1_5 import PKCS1_5PaddingOracleAttack,\
                                   PKCS1_5PaddingOracle
from common.challenge import MatasanoChallenge
from common.ciphers.pubkey.rsa import RSA
from common.tools.padders import PKCS1_5Padder


class Set6Challenge8(MatasanoChallenge):
    
    STRING = 'Pochoclin!'
    RSA_BITS = 768
    
    def expected_value(self):
        return self.STRING

    def value(self):
        rsa = RSA(bits=self.RSA_BITS)
        oracle = PKCS1_5PaddingOracle(rsa)
        padded_string = PKCS1_5Padder(self.STRING).value(size=self.RSA_BITS/8)
        ciphertext = rsa.encrypt(padded_string)
        return PKCS1_5PaddingOracleAttack(oracle).decrypt(ciphertext)
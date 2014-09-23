from common.attacks.pkcs1_5 import PKCS1_5PaddingOracleAttack,\
                                   PKCS1_5PaddingOracle
from common.challenge import MatasanoChallenge
from common.ciphers.pubkey.rsa import RSA
from common.tools.padders import PKCS1_5Padder


class Set6Challenge7(MatasanoChallenge):
    
    STRING = 'Pochoclin!'
    
    def expected_value(self):
        return self.STRING

    def value(self):
        rsa = RSA(bits=256)
        oracle = PKCS1_5PaddingOracle(rsa)
        padded_string = PKCS1_5Padder(self.STRING).value(size=32)
        ciphertext = rsa.encrypt(padded_string)
        return PKCS1_5PaddingOracleAttack(oracle).decrypt(ciphertext)

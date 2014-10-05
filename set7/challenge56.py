from common.challenge import MatasanoChallenge
from common.ciphers.stream.rc4 import RC4
from common.tools.base64 import Base64Decoder
from common.tools.misc import RandomByteGenerator


class RC4SingleByteBiasAttack(object):
    
    def __init__(self, oracle):
        self.oracle = oracle
        
    def value(self):
        # TBC
        pass
        

class RC4EncryptionOracle(object):
    
    RC4_KEY_SIZE = 16
    
    def __init__(self, suffix):
        self.suffix = suffix
        
    def encrypt(self, message):
        key = RandomByteGenerator().value(self.RC4_KEY_SIZE)
        return RC4(key).encrypt(message + self.suffix)
        

class Set7Challenge56(MatasanoChallenge):
    
    PLAINTEXT = 'QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F'
    
    def __init__(self):
        MatasanoChallenge.__init__(self)
        self.plaintext = Base64Decoder().decode(self.PLAINTEXT)
    
    def expected_value(self):
        return self.plaintext
    
    def value(self):
        oracle = RC4EncryptionOracle(self.plaintext)
        return RC4SingleByteBiasAttack(oracle).value()
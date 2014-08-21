from common.base64 import Base64Decoder
from common.challenge import MatasanoChallenge
from common.ciphers.block.cipher import AES
from common.ciphers.block.modes import CBC


class Set2Challenge2(MatasanoChallenge):
    
    FILE = 'set2/data/10.txt'
    KEY = 'YELLOW SUBMARINE'
    IV = '\0' * 16
    
    def expected_value(self):
        return open('set1/data/6ans.txt', 'r').read()

    def value(self):
        content = open(self.FILE, 'r').read()
        ciphertext = Base64Decoder().decode(content)
        return AES(self.KEY).decrypt(ciphertext, mode=CBC(self.IV))

from common.base64 import Base64Decoder
from common.challenge import MatasanoChallenge
from common.ciphers.block.cipher import AES
from common.ciphers.block.modes import ECB

    
class Set1Challenge7(MatasanoChallenge):
    
    def expected_value(self):
        return open('set1/data/6ans.txt', 'r').read()

    def value(self):
        target_file = 'set1/data/7.txt'
        key = 'YELLOW SUBMARINE'
        content = open(target_file, 'r').read()
        ciphertext = Base64Decoder().decode(content)
        return AES(key).decrypt(ciphertext, mode=ECB()).bytes()
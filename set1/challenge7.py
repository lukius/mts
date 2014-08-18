from common.base64 import Base64Decoder
from common.challenge import MatasanoChallenge
from common.ciphers.block.cipher import AES
from common.ciphers.block.modes import ECB
from common.converters import HexToASCII

    
class Set1Challenge7(MatasanoChallenge):
    
    def expected_value(self):
        return open('set1/data/6ans.txt', 'r').read()

    def value(self):
        target_file = 'set1/data/7.txt'
        key = 'YELLOW SUBMARINE'
        content = open(target_file, 'r').read()
        decoded_content = Base64Decoder().value(content)
        ciphertext = HexToASCII(decoded_content).value()
        return AES(key).decrypt(ciphertext, mode=ECB())
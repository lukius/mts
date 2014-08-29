from common.base64 import Base64Decoder
from common.challenge import MatasanoChallenge
from common.attacks.xor import RepeatingKeyXORDecrypter
        

class Set1Challenge6(MatasanoChallenge):
    
    FILE = 'set1/data/6.txt'
    
    def expected_value(self):
        return open('set1/data/6ans.txt', 'r').read()

    def value(self):
        decoded_content = Base64Decoder().decode_file(self.FILE)
        return RepeatingKeyXORDecrypter().decrypt(decoded_content)
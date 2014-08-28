from common.base64 import Base64Decoder
from common.challenge import MatasanoChallenge
from common.attacks.xor import RepeatingKeyXORDecrypter
        

class Set1Challenge6(MatasanoChallenge):
    
    def expected_value(self):
        return open('set1/data/6ans.txt', 'r').read()

    def value(self):
        target_file = 'set1/data/6.txt'
        content = open(target_file, 'r').read()
        decoded_content = Base64Decoder().decode(content)
        return RepeatingKeyXORDecrypter().decrypt(decoded_content)
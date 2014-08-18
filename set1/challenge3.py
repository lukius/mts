from common.challenge import MatasanoChallenge
from common.xor import SingleByteXORDecipher    


class Set1Challenge3(MatasanoChallenge):
    
    def expected_value(self):
        return 'Cooking MC\'s like a pound of bacon'

    def value(self):
        target_string = '1b37373331363f78151b7f2b783431333d78397828372d363c7'+\
                        '8373e783a393b3736'
        return SingleByteXORDecipher().value(target_string)[1]
from common.challenge import MatasanoChallenge
from common.converters import HexToBytes
from common.xor import SingleByteXORDecipher


class SingleByteXORFinder(object):
    
    def __init__(self, hex_strings):
        self.hex_strings = hex_strings
        
    def value(self):
        max_score = 0
        for hex_string in self.hex_strings:
            byte_string = HexToBytes(hex_string).value()
            _, plaintext, score = SingleByteXORDecipher().\
                                    value(byte_string, with_score=True)
            if score > max_score:
                candidate_plaintext = plaintext
                max_score = score
        return candidate_plaintext
    

class Set1Challenge4(MatasanoChallenge):
    
    def expected_value(self):
        return 'Now that the party is jumping\n'

    def value(self):
        target_file = 'set1/data/4.txt'
        hex_strings = open(target_file, 'r').read().splitlines()
        return SingleByteXORFinder(hex_strings).value()
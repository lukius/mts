from common.xor import SingleByteXORDecipher


class SingleByteXORFinder(object):
    
    def __init__(self, hex_strings):
        self.hex_strings = hex_strings
        
    def value(self):
        max_score = 0
        for hex_string in self.hex_strings:
            key, plaintext, score = SingleByteXORDecipher(hex_string).\
                                    value(with_score=True)
            if score > max_score:
                candidate_key = key
                candidate_plaintext = plaintext
                max_score = score
        return (candidate_key, candidate_plaintext)
    
    
if __name__ == '__main__':
    target_file = 'data/4.txt'
    hex_strings = open(target_file, 'r').read().splitlines()
    print SingleByteXORFinder(hex_strings).value()
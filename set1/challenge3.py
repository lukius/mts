from common.converters import HexToASCII
from common.freq import EnglishFrequencyScorer
from common.padders import LeftPadder
from common.tools import HexXOR


class XORDecipher(object):
    
    def __init__(self, hex_string):
        self.hex_string = hex_string
        
    def _xor_decrypt_with(self, key):
        length = len(self.hex_string)/2
        extended_key = key*length
        hex_string = HexXOR(self.hex_string, extended_key).value()
        return HexToASCII(hex_string).value()
    
    def value(self):
        max_score = 0
        for byte in range(255):
            hex_byte = LeftPadder(hex(byte)[2:]).value(2)
            plaintext = self._xor_decrypt_with(hex_byte)
            score = EnglishFrequencyScorer(plaintext).value()
            if score > max_score:
                candidate_key = hex_byte
                candidate_plaintext = self._xor_decrypt_with(candidate_key)
                max_score = score
        return (candidate_key, candidate_plaintext)
    
    
if __name__ == '__main__':
    target_string = '1b37373331363f78151b7f2b783431333d78397828372d363c7837'+\
                    '3e783a393b3736'
    print XORDecipher(target_string).value()
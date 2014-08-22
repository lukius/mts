from converters import HexToBytes, IntToHex, HexToInt
from freq import EnglishFrequencyScorer
from padders import LeftPadder


class HexXOR(object):
    
    def __init__(self, string1, string2):
        if len(string1) != len(string2):
            raise RuntimeError('strings must have equal length')
        self.string1 = string1
        self.string2 = string2
        
    def value(self):
        integer1 = HexToInt(self.string1).value()
        integer2 = HexToInt(self.string2).value()
        xored = integer1 ^ integer2
        string = IntToHex(xored).value()
        return LeftPadder(string).value(len(self.string1))
    
    
class SingleByteXORDecipher(object):
    
    def _xor_decrypt_with(self, key, hex_string):
        length = len(hex_string)/2
        extended_key = key*length
        decrypted = HexXOR(hex_string, extended_key).value()
        return HexToBytes(decrypted).value()
    
    def _greater_than(self, number1, number2):
        return number2 is None or number1 > number2
    
    def value(self, hex_string, with_score=False):
        max_score = None
        for byte in range(255):
            hex_byte = LeftPadder(IntToHex(byte).value()).value(2)
            plaintext = self._xor_decrypt_with(hex_byte, hex_string)
            score = EnglishFrequencyScorer(plaintext).value()
            if self._greater_than(score, max_score):
                candidate_key = hex_byte
                candidate_plaintext = plaintext
                max_score = score
        values = (candidate_key, candidate_plaintext)
        if with_score:
            values += (max_score,)
        return values
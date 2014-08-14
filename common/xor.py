from converters import HexToASCII, IntToHex
from freq import EnglishFrequencyScorer
from padders import LeftPadder
from tools import concatenate


class HexXOR(object):
    
    def __init__(self, string1, string2):
        if len(string1) != len(string2):
            raise RuntimeError('strings must have equal length')
        self.string1 = string1
        self.string2 = string2
        
    def value(self):
        from common.converters import HexToBinary, BinaryToHex
        bin_string1 = HexToBinary(self.string1).value()
        bin_string2 = HexToBinary(self.string2).value()
        pairs = zip(bin_string1, bin_string2)
        pairs_xored = map(lambda (bit1, bit2): str(int(bit1) ^ int(bit2)),
                          pairs)
        bin_string = concatenate(pairs_xored)
        return BinaryToHex(bin_string).value()
    
    
class XORCipher(object):
    
    def __init__(self, key):
        self.key = key
        
    def _extend_key_for(self, plaintext):
        plaintext_length = len(plaintext)
        key_length = len(self.key)
        quotient, remainder = divmod(plaintext_length, key_length)
        return self.key*quotient + self.key[:remainder]
        
    def value(self, plaintext):
        extended_key = self._extend_key_for(plaintext)
        return HexXOR(extended_key, plaintext).value()


class SingleByteXORDecipher(object):
    
    def __init__(self, hex_string):
        self.hex_string = hex_string
        
    def _xor_decrypt_with(self, key):
        length = len(self.hex_string)/2
        extended_key = key*length
        hex_string = HexXOR(self.hex_string, extended_key).value()
        return HexToASCII(hex_string).value()
    
    def value(self, with_score=False):
        max_score = 0
        for byte in range(255):
            hex_byte = LeftPadder(IntToHex(byte).value()).value(2)
            plaintext = self._xor_decrypt_with(hex_byte)
            score = EnglishFrequencyScorer(plaintext).value()
            if score > max_score:
                candidate_key = hex_byte
                candidate_plaintext = plaintext
                max_score = score
        values = (candidate_key, candidate_plaintext)
        if with_score:
            values += (max_score,)
        return values
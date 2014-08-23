from converters import IntToHex, HexToInt, BytesToInt, IntToBytes
from freq import EnglishFrequencyScorer


class XOR(object):
    
    def __init__(self, string1, string2):
        self.string1 = string1
        self.string2 = string2
        
    def _to_int(self, string):
        converter = self._to_int_converter() 
        return converter(string).value()
    
    def _from_int(self, integer):
        converter = self._from_int_converter() 
        return converter(integer).value()
        
    def value(self):
        integer1 = self._to_int(self.string1)
        integer2 = self._to_int(self.string2)
        xored = integer1 ^ integer2
        return self._from_int(xored)


class HexXOR(XOR):
    
    def _to_int_converter(self):
        return HexToInt
    
    def _from_int_converter(self):
        return IntToHex


class ByteXOR(XOR):
    
    def _to_int_converter(self):
        return BytesToInt
    
    def _from_int_converter(self):
        return IntToBytes   
    
    
class SingleByteXORDecipher(object):
    
    def _xor_decrypt_with(self, key, string):
        extended_key = key*len(string)
        return ByteXOR(string, extended_key).value()
    
    def _greater_than(self, number1, number2):
        return number2 is None or number1 > number2
    
    def value(self, string, with_score=False):
        max_score = None
        for byte in range(255):
            byte = chr(byte)
            plaintext = self._xor_decrypt_with(byte, string)
            score = EnglishFrequencyScorer(plaintext).value()
            if self._greater_than(score, max_score):
                candidate_key = byte
                candidate_plaintext = plaintext
                max_score = score
        values = (candidate_key, candidate_plaintext)
        if with_score:
            values += (max_score,)
        return values
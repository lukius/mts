from common.bintools import HexToBinary, BinaryToHex
from common.tools import concatenate


class BufferXOR(object):
    
    def __init__(self, string1, string2):
        self.string1 = string1
        self.string2 = string2
        
    def value(self):
        bin_string1 = HexToBinary(self.string1).value()
        bin_string2 = HexToBinary(self.string2).value()
        pairs = zip(bin_string1, bin_string2)
        pairs_xored = map(lambda (bit1, bit2): str(int(bit1) ^ int(bit2)),
                          pairs)
        bin_string = concatenate(pairs_xored)
        return BinaryToHex(bin_string).value()
    
    
if __name__ == '__main__':
    target_string1 = '1c0111001f010100061a024b53535009181c'
    target_string2 = '686974207468652062756c6c277320657965'
    print BufferXOR(target_string1, target_string2).value()
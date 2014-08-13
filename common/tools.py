def concatenate(strings):
    return ''.join(strings)


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
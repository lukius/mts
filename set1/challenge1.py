from common.bintools import BytesToBinary
from common.padder import RightPadder


class Base64Encoder(object):
    
    def __init__(self, byte_string):
        self.byte_string = byte_string
        
    def _char_at(self, index):
        def map_char(char, index, base):
            return chr(ord(char) + index - base)
        
        if index < 26:
            char = map_char('A', index, 0)
        elif index < 52:
            char = map_char('a', index, 26)
        elif index < 62:
            char = map_char('0', index, 52)
        else:
            char = '+' if index == 62 else '/'
        return char
    
    def _pad_base64(self, string, length):
        if length % 24 == 8:
            string += '=='
        elif length % 24 == 16:
            string += '='
        return string       
        
    def value(self):
        base64_str = str()
        bin_str = BytesToBinary(self.byte_string).value()
        for i in xrange(0, len(bin_str), 6):
            group = bin_str[i:i+6]
            group = RightPadder(group).value(6)
            index = int(group, 2)
            base64_str += self._char_at(index)
        return self._pad_base64(base64_str, len(bin_str))
    

if __name__ == '__main__':
    target_string = '49276d206b696c6c696e6720796f757220627261696e206c696b652'+\
                    '06120706f69736f6e6f7573206d757368726f6f6d'
    print Base64Encoder(target_string).value()
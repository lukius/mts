from common.tools.converters import HexToBytes, IntToBinary, BinaryToHex,\
                              BytesToBinary, BinaryToBytes
from common.tools.padders import RightPadder, LeftPadder
from common.tools.misc import FileLines


class Base64Encoder(object):
    
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
    
    def encode_from_hex(self, hex_string):
        string = HexToBytes(hex_string).value()
        return self.encode(string)
        
    def encode(self, string):
        base64_str = str()
        bin_str = BytesToBinary(string).value()
        for i in xrange(0, len(bin_str), 6):
            group = bin_str[i:i+6]
            group = RightPadder(group).value(6)
            index = int(group, 2)
            base64_str += self._char_at(index)
        return self._pad_base64(base64_str, len(bin_str))
    
    
class Base64Decoder(object):
    
    def _index_of(self, char):
        def map_index(ord_char, base_char, offset):
            return ord_char - ord(base_char) + offset
        
        ord_char = ord(char)
        if ord('A') <= ord_char <= ord('Z'):
            index = map_index(ord_char, 'A', 0)
        elif ord('a') <= ord_char <= ord('z'):
            index = map_index(ord_char, 'a', 26)
        elif ord('0') <= ord_char <= ord('9'):
            index = map_index(ord_char, '0', 52)
        elif ord_char in [43, 47]:
            index = 62 if char == '+' else 63
        else:
            index = None
        return index
    
    def _remove_base64_padding(self, string, bin_string):
        if string.endswith('=='):
            while len(bin_string) % 24 != 8:
                bin_string = bin_string[:-1]
        elif string.endswith('='):
            while len(bin_string) % 24 != 16:
                bin_string = bin_string[:-1]
        return bin_string
    
    def decode_to_hex(self, string):
        bin_string = self._decode(string)
        return BinaryToHex(bin_string).value()
    
    def decode(self, string):
        bin_string = self._decode(string)
        return BinaryToBytes(bin_string).value()
    
    def decode_file(self, filename):
        content = open(filename, 'r').read()
        return self.decode(content)
    
    def decode_file_lines(self, filename):
        lines = FileLines(filename).value()
        return map(lambda line: self.decode(line), lines)
        
    def _decode(self, string):
        bin_string = str()
        string = string.strip()
        for char in string:
            if char == '=':
                break
            index = self._index_of(char)
            if index is None:
                continue
            bin_index = IntToBinary(index).value()
            padded_bin_index = LeftPadder(bin_index).value(6)
            bin_string += padded_bin_index
        bin_string = self._remove_base64_padding(string, bin_string)
        return bin_string
from common.base64 import Base64Decoder
from common.tools import HammingDistance


class RepeatingKeyXORDecipher(object):
    
    def value(self, hex_string):
        pass
    
    
if __name__ == '__main__':
    target_file = 'data/6.txt'
    content = open(target_file, 'r').read()
    decoded_content = Base64Decoder().value(content)
    print HammingDistance('this is a test', 'wokka wokka!!!').value()
    print RepeatingKeyXORDecipher().value(decoded_content)
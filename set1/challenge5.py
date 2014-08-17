from common.converters import ASCIIToHex
from common.ciphers.xor import XORCipher

    
if __name__ == '__main__':
    target_string = "Burning 'em, if you ain't quick and nimble\n"+\
                    "I go crazy when I hear a cymbal"
    target_hex = ASCIIToHex(target_string).value()
    key = ASCIIToHex('ICE').value()
    print XORCipher(key).encrypt(target_hex)
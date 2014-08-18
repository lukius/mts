from common.challenge import MatasanoChallenge
from common.converters import ASCIIToHex
from common.ciphers.xor import XORCipher


class Set1Challenge5(MatasanoChallenge):
    
    def expected_value(self):
        return '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2' +\
               '6226324272765272a282b2f20430a652e2c652a3124333a653e2b202763' +\
               '0c692b20283165286326302e27282f'

    def value(self):
        target_string = "Burning 'em, if you ain't quick and nimble\n"+\
                        "I go crazy when I hear a cymbal"
        target_hex = ASCIIToHex(target_string).value()
        key = ASCIIToHex('ICE').value()
        return XORCipher(key).encrypt(target_hex)
from common.base64 import Base64Decoder
from common.challenge import MatasanoChallenge
from common.tools import Concatenation, FileLines
from common.attacks.xor import RepeatingKeyXORDecrypter


class FixedNonceCTRDecrypter(object):
        
    def decrypt(self, ciphertexts):
        ciphertext = ConcatenationAfterTruncation(ciphertexts).value()
        return RepeatingKeyXORDecrypter().decrypt(ciphertext)


class ConcatenationAfterTruncation(object):

    def __init__(self, strings):
        self.strings = strings

    def value(self):
        min_length = min(map(len, self.strings))
        strings = [string[:min_length] for string in self.strings]
        return Concatenation(strings).value()


class Set3Challenge4(MatasanoChallenge):
    
    FILE = 'set3/data/20.txt'
    ANSWER_FILE = 'set3/data/20ans.txt'
    
    def expected_value(self):
        strings = FileLines(self.ANSWER_FILE).value()
        return ConcatenationAfterTruncation(strings).value()
    
    def value(self):
        strings = FileLines(self.FILE).value()
        decoder = Base64Decoder()
        ciphertexts = map(lambda string: decoder.decode(string), strings)
        return FixedNonceCTRDecrypter().decrypt(ciphertexts)
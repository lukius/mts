from common.challenge import MatasanoChallenge
from common.padders import PKCS7Padder


class Set2Challenge1(MatasanoChallenge):
    
    STRING = 'YELLOW SUBMARINE'
    
    def expected_value(self):
        return '%s%s' % (self.STRING, '\4'*4)

    def value(self):
        return PKCS7Padder(self.STRING).value(20)
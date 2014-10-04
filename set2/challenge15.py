from common.challenge import MatasanoChallenge
from common.tools.padders import PKCS7Padder, PKCS7Unpadder 
from common.tools.padders import InvalidPaddingException       


class Set2Challenge15(MatasanoChallenge):

    STRING = 'ICE ICE BABY'
    SIZE = 16

    def _test_valid_padding(self):
        padded_string = PKCS7Padder(self.STRING).value(self.SIZE)
        unpadded_string = PKCS7Unpadder(padded_string).value()
        return unpadded_string == self.STRING
        
    def _test_invalid_padding(self):
        ill_padded_string = self.STRING + chr(5)*4
        if not self._assert_raises(InvalidPaddingException,
                                   PKCS7Unpadder(ill_padded_string).value):
            return False
        
        ill_padded_string = self.STRING + chr(1) + chr(2) + chr(3) + chr(4)
        if not self._assert_raises(InvalidPaddingException,
                                   PKCS7Unpadder(ill_padded_string).value):
            return False
        return True

    def validate(self):
        valid_padding = self._test_valid_padding()
        invalid_padding = self._test_invalid_padding()
        return valid_padding and invalid_padding
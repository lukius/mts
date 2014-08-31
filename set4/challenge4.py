from common.challenge import MatasanoChallenge
from common.mac.sha1 import SHA1BasedMAC
from common.tools import RandomByteGenerator


class Set4Challenge4(MatasanoChallenge):

    MESSAGE = 'foo bar baz'

    def _check_valid_mac(self, sha1mac):
        mac = sha1mac.value(self.MESSAGE)
        return sha1mac.validate(self.MESSAGE, mac)
    
    def _check_invalid_mac(self, sha1mac):
        mac = sha1mac.value(self.MESSAGE)
        return not sha1mac.validate(self.MESSAGE + ' qux', mac)    

    def validate(self):
        key = RandomByteGenerator().value()
        sha1mac = SHA1BasedMAC(key)
        valid_mac_ok = self._check_valid_mac(sha1mac)
        invalid_mac_ok = self._check_invalid_mac(sha1mac)
        return valid_mac_ok and invalid_mac_ok
        
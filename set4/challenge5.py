from common.attacks.mac import MDHashBasedMACMessageForger
from common.challenge import MatasanoChallenge
from common.hash.sha1 import SHA1
from common.mac.hash import HashBasedMAC
from common.tools import RandomByteGenerator


class SHA1BasedMACMessageForger(MDHashBasedMACMessageForger):
    
    def _hash_function(self):
        return SHA1


class Set4Challenge5(MatasanoChallenge):
    
    STRING = 'comment1=cooking%20MCs;userdata=foo;'+\
             'comment2=%20like%20a%20pound%20of%20bacon'
    TARGET_STRING = ';admin=true'

    def validate(self):
        key = RandomByteGenerator().value(20)
        sha1mac = HashBasedMAC(key, SHA1)
        string_mac = sha1mac.value(self.STRING)
        message, mac = SHA1BasedMACMessageForger(sha1mac).\
                       forge(self.STRING, string_mac, self.TARGET_STRING)
                       
        return message.startswith(self.STRING) and\
               message.endswith(self.TARGET_STRING) and\
               sha1mac.validate(message, mac)
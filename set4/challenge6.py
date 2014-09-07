from common.attacks.mac import MDHashBasedMACMessageForger, ResumableMDHash
from common.challenge import MatasanoChallenge
from common.hash.md4 import MD4
from common.mac.md4 import MD4BasedMAC
from common.tools import RandomByteGenerator


class MD4BasedMACMessageForger(MDHashBasedMACMessageForger):
    
    def _resumable_hash(self):
        return ResumableMDHash(MD4).value()


class Set4Challenge6(MatasanoChallenge):
    
    STRING = 'comment1=cooking%20MCs;userdata=foo;'+\
             'comment2=%20like%20a%20pound%20of%20bacon'
    TARGET_STRING = ';admin=true'

    def validate(self):
        key = RandomByteGenerator().value(20)
        sha1mac = MD4BasedMAC(key)
        string_mac = sha1mac.value(self.STRING)
        message, mac = MD4BasedMACMessageForger(sha1mac).\
                       forge(self.STRING, string_mac, self.TARGET_STRING)
                       
        return message.startswith(self.STRING) and\
               message.endswith(self.TARGET_STRING) and\
               sha1mac.validate(message, mac)
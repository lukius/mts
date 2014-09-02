import struct

from common.challenge import MatasanoChallenge
from common.converters import BytesToInt
from common.hash.sha1 import SHA1
from common.mac.sha1 import SHA1BasedMAC
from common.padders import SHA1Padder
from common.tools import RandomByteGenerator


class SHA1BasedMACMessageForger(object):
    
    MAX_KEY_LENGTH = 512
    
    def __init__(self, sha1mac):
        self.mac_validator = sha1mac
        
    def _get_sha1_registers_from(self, hash_bytes):
        return [BytesToInt(hash_bytes[i:i+4]).value()
                for i in range(0, len(hash_bytes), 4)]
        
    def _build_message_to_forge(self, message, new_message, key_length):
        total_prefix_length = key_length + len(message)
        padded_message = SHA1Padder(message).value(total_prefix_length)
        return padded_message + new_message
    
    def _build_message_to_hash(self, message_to_forge, new_message,
                               key_length):
        total_bit_length = 8*(key_length + len(message_to_forge))
        new_message_padded = SHA1Padder(new_message).value()
        return new_message_padded[:-8] + struct.pack('>Q', total_bit_length)
            
    def forge(self, message, message_mac, new_message):
        sha1_registers = self._get_sha1_registers_from(message_mac)
        resumable_sha1 = ResumableSHA1(sha1_registers)
        # Since key length is unknown, iterate until we find it.
        for key_length in range(self.MAX_KEY_LENGTH):
            # First step: assemble the message that will be forged:
            # <original message> + <SHA1 padding for this key length>
            # + <appendix>
            message_to_forge = self._build_message_to_forge(message,
                                                            new_message,
                                                            key_length)
            # Second step: assemble the message to resume SHA1 computations:
            # <appendix> + <SHA1 padding for the appendix>
            # + <total bit length, including the guessed key length>
            # Since message_to_forge has already k*512 bits before the
            # appendix, the SHA1 padding for the appendix alone will work fine.
            message_to_hash = self._build_message_to_hash(message_to_forge,
                                                          new_message,
                                                          key_length)
            hash_value = resumable_sha1.hash(message_to_hash)
            if self.mac_validator.validate(message_to_forge, hash_value):
                return message_to_forge, hash_value


class ResumableSHA1(SHA1):
    
    def __init__(self, registers):
        self.registers = registers
        
    def _initialize_values(self):
        self.h0 = self.registers[0]
        self.h1 = self.registers[1]
        self.h2 = self.registers[2]
        self.h3 = self.registers[3]
        self.h4 = self.registers[4]
        
    def _pad_message(self, message):
        # Treat incoming messages as if they were already padded.
        return message
    

class Set4Challenge5(MatasanoChallenge):
    
    STRING = 'comment1=cooking%20MCs;userdata=foo;'+\
             'comment2=%20like%20a%20pound%20of%20bacon'
    TARGET_STRING = ';admin=true'

    def validate(self):
        key = RandomByteGenerator().value(20)
        sha1mac = SHA1BasedMAC(key)
        string_mac = sha1mac.value(self.STRING)
        message, mac = SHA1BasedMACMessageForger(sha1mac).\
                       forge(self.STRING, string_mac, self.TARGET_STRING)
                       
        return message.startswith(self.STRING) and\
               message.endswith(self.TARGET_STRING) and\
               sha1mac.validate(message, mac)
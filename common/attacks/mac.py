import httplib
import time

from common.attacks.tools.hash import ResumableMDHash
from common.converters import BytesToHex
from common.padders import MDPadder, RightPadder


class MDHashBasedMACMessageForger(object):
    
    MAX_KEY_LENGTH = 512
    
    def __init__(self, mac_validator):
        self.mac_validator = mac_validator
        self.resumable_hash = self._resumable_hash()
        self.endianness = self.resumable_hash.endianness()
        
    def _pad_message(self, message, size=None):
        return MDPadder(message, self.endianness).value(size)
        
    def _get_registers_from(self, hash_bytes):
        return [self.endianness.to_int(hash_bytes[i:i+4]).value()
                for i in range(0, len(hash_bytes), 4)]
        
    def _build_message_to_forge(self, message, new_message, key_length):
        total_prefix_length = key_length + len(message)
        padded_message = self._pad_message(message, total_prefix_length)
        return padded_message + new_message
    
    def _build_message_to_hash(self, message_to_forge, new_message,
                               key_length):
        total_bit_length = 8*(key_length + len(message_to_forge))
        new_message_padded = self._pad_message(new_message)
        return new_message_padded[:-8] +\
               self.endianness.from_int(total_bit_length, size=8).value()
            
    def forge(self, message, message_mac, new_message):
        registers = self._get_registers_from(message_mac)
        resumable_hash = self.resumable_hash(registers)
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
            hash_value = resumable_hash.hash(message_to_hash)
            if self.mac_validator.validate(message_to_forge, hash_value):
                return message_to_forge, hash_value
    
    def _resumable_hash(self):
        hash_function = self._hash_function()
        return ResumableMDHash(hash_function).value()
    
    def _hash_function(self):
        raise NotImplementedError
    
    
class TimeLeakBasedHMACCracker(object):
    
    URL_TEMPLATE = '/test?file=foo&signature='
    MAC_SIZE = 20
    
    def __init__(self, server):
        self.server = server

    def _pad(self, hmac):
        return RightPadder(hmac).value(self.MAC_SIZE)

    def _make_request_for(self, hmac):
        hex_hmac = BytesToHex(hmac).value()
        connection = httplib.HTTPConnection(self.server.ADDRESS,
                                            self.server.PORT)
        connection.request('GET', self.URL_TEMPLATE + hex_hmac)
        return connection.getresponse()
    
    def _measure_request_time_for(self, hmac):
        start_time = time.time()
        self._make_request_for(hmac)
        end_time = time.time()
        return end_time - start_time
    
    def _crack_byte(self, index, cracked_bytes):
        if index == self.MAC_SIZE-1:
            return self._crack_last_byte(cracked_bytes)
        return self._crack_non_last_byte(index, cracked_bytes)
    
    def _crack_last_byte(self, cracked_bytes):
        for byte in range(256):
            char = chr(byte)
            response = self._make_request_for(cracked_bytes + char)
            if response.status == 200:
                return char
        
    def _crack_non_last_byte(self, index, cracked_bytes):
        byte_scores = list()
        for byte in range(256):
            char = chr(byte)
            target_hmac = self._pad(cracked_bytes+char)
            score = self._compute_score_for(target_hmac)
            byte_scores.append((char, score))
        return max(byte_scores, key=lambda _tuple: _tuple[1])[0]
    
    def _compute_score_for(self, hmac):
        return self._measure_request_time_for(hmac)
        
    def crack(self):
        cracked_mac = str()
        for byte_index in range(self.MAC_SIZE):
            cracked_byte = self._crack_byte(byte_index, cracked_mac)
            cracked_mac += cracked_byte
        return cracked_mac
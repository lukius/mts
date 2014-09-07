from common.converters import BytesToInt
from common.endianness import BigEndian


class MDHashBasedMACMessageForger(object):
    
    MAX_KEY_LENGTH = 512
    
    def __init__(self, mac_validator):
        self.mac_validator = mac_validator
        self.resumable_hash = self._resumable_hash()
        self.padder = self.resumable_hash.padder()
        self.endianness = self._endianness()
        
    def _endianness(self):
        # Overridable by subclasses if necessary.
        return BigEndian
        
    def _get_registers_from(self, hash_bytes):
        return [BytesToInt(hash_bytes[i:i+4],
                           endianness=self.endianness).value()
                for i in range(0, len(hash_bytes), 4)]
        
    def _build_message_to_forge(self, message, new_message, key_length):
        total_prefix_length = key_length + len(message)
        padded_message = self.padder(message).value(total_prefix_length)
        return padded_message + new_message
    
    def _build_message_to_hash(self, message_to_forge, new_message,
                               key_length):
        total_bit_length = 8*(key_length + len(message_to_forge))
        new_message_padded = self.padder(new_message).value()
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
        raise NotImplementedError
    
    
class ResumableMDHash(object):
    
    def __init__(self, hash_function_class):
        self.hash_function_class = hash_function_class
        
    def value(self):
        class ResumableHash(self.hash_function_class):
            def __init__(_self, registers):
                self.hash_function_class.__init__(_self)
                _self.custom_registers = registers
                
            def _initialize_registers(_self):
                _self.registers = list(_self.custom_registers)
                
            def _pad_message(_self, message):
                # Treat incoming messages as if they were already padded.
                return message
            
        return ResumableHash
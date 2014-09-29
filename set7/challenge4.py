from common.attacks.tools.hash import ResumableMDHash
from common.challenge import MatasanoChallenge
from common.ciphers.block.aes import AES
from common.hash.md import MDHashFunction
from common.tools.endianness import BigEndian
from common.tools.misc import RandomByteGenerator
from common.tools.padders import RightPadder


class MulticollisionGenerator(object):
    
    MAX_BYTES = 64
    
    def __init__(self, hash_function):
        self.hash_function = hash_function()
        self.resumable_hash = ResumableMDHash(hash_function).value()
        self.byte_generator = RandomByteGenerator()
        
    def _get_rand_message_and_state(self, hash_function):
        message = self.byte_generator.value(self.MAX_BYTES)
        state = hash_function._process_chunk(message)
        return message, state
        
    def _find_collisions_for(self, hash_function):
        hash_function._initialize_registers()
        message1, state1 = self._get_rand_message_and_state(hash_function)
        while True:
            message2, state2 = self._get_rand_message_and_state(hash_function)
            if state1 == state2:
                break
        return state1, [message1, message2]
    
    def value(self, n):
        state, collisions = self._find_collisions_for(self.hash_function)
        for _ in range(n-1):
            # Find a new collision for current state registers, and then
            # combine the results.
            resumable_hash = self.resumable_hash(state)
            state, new_collisions = self._find_collisions_for(resumable_hash)
            collisions = [c1 + c2 for c1 in collisions
                                  for c2 in new_collisions]
        return collisions


class CheapHashFunction(MDHashFunction):
    
    H0 = 0xcaca
    
    @classmethod
    def bits(cls):
        return 16
    
    @classmethod
    def endianness(cls):
        return BigEndian    

    def _initialize_registers(self):
        self.registers = [self.H0]
    
    def _build_key_from_register(self):
        key = self.endianness().from_int(self.registers[0], size=2).value()
        return RightPadder(key).value(size=16, char='\x01')
    
    def _process_chunk(self, chunk):
        key = self._build_key_from_register()
        result = AES(key).encrypt(chunk).bytes()
        return (self.endianness().to_int(result[:2]).value(),)


class Set7Challenge4(MatasanoChallenge):
    
    def expected_value(self):
        # TBD
        return None
    
    def value(self):
        multicollision_generator = MulticollisionGenerator(CheapHashFunction)
        print multicollision_generator.value(2)
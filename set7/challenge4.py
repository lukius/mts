import random

from collections import defaultdict

from common.attacks.multicollisions import MulticollisionGenerator
from common.challenge import MatasanoChallenge
from common.ciphers.block.aes import AES
from common.hash import HashFunction
from common.hash.md import MDHashFunction
from common.tools.endianness import BigEndian
from common.tools.misc import Concatenation, AllEqual
from common.tools.padders import RightPadder


class ToyHashFunctionFactory(object):
    
    @classmethod
    def build(cls, bits):
        max_int = (1<<bits) - 1
        initial_state = random.randint(0, max_int)
        byte_size = bits/8
        
        class ToyHashFunction(MDHashFunction):

            @classmethod
            def bits(cls):
                return bits
            
            @classmethod
            def endianness(cls):
                return BigEndian    
        
            def _initialize_registers(self):
                self.registers = [initial_state]
            
            def _build_key_from_register(self):
                key = self.endianness().from_int(self.registers[0],
                                                 size=byte_size).value()
                return RightPadder(key).value(size=16, char='\x01')
            
            def _process_chunk(self, chunk):
                key = self._build_key_from_register()
                result = AES(key).encrypt(chunk).bytes()
                return [self.endianness().to_int(result[:byte_size]).value()]
            
        return ToyHashFunction


class ComposedHashFunction(HashFunction):
    
    def __init__(self, *functions):
        self.functions = functions
        
    def hash(self, message):
        hashes = map(lambda function: function().hash(message), self.functions)
        return Concatenation(hashes).value()


class Set7Challenge4(MatasanoChallenge):
    
    def __init__(self):
        MatasanoChallenge.__init__(self)
        self.WeakHashFunction = ToyHashFunctionFactory.build(16)
        self.StrongerHashFunction = ToyHashFunctionFactory.build(32)
        self.composed_hash = ComposedHashFunction(self.WeakHashFunction,
                                                  self.StrongerHashFunction)
        
    def _filter_collisions(self, collisions):
        hashes = defaultdict(lambda: list())
        for collision in collisions:
            collision_hash = self.composed_hash.hash(collision)
            hashes[collision_hash].append(collision)
        for collision_hash in hashes:
            messages = hashes[collision_hash]
            if len(messages) > 1:
                return messages
        return list()
    
    def _generate_collisions_from_weak_hash(self):
        collision_generator = MulticollisionGenerator(self.WeakHashFunction)
        state = list()
        collisions = None
        # Generate 2**(target_bitsize/2) collisions; keep duplicating
        # if no collisions are found.
        n = self.StrongerHashFunction.bits()/2
        while True:
            # On each step, duplicate the number of collisions. This is 
            # achieved by supplying previous collisions and state to the
            # multicollision generator.
            collisions, state = collision_generator.value(n, collisions, state)
            composed_hash_collisions = self._filter_collisions(collisions)
            if composed_hash_collisions:
                break
            n += 1
        return composed_hash_collisions
    
    def validate(self):
        collisions = self._generate_collisions_from_weak_hash()
        hashes = map(lambda message: self.composed_hash.hash(message),
                     collisions)
        return AllEqual(hashes).value()
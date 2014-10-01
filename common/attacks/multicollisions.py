from common.attacks.tools.hash import ResumableMDHash
from common.tools.misc import RandomByteGenerator


class MulticollisionGenerator(object):
    
    BLOCK_SIZE = 64
    
    def __init__(self, hash_function):
        self.hash_function = hash_function
        self.resumable_hash = ResumableMDHash(hash_function).value()
        self.byte_generator = RandomByteGenerator()
        
    def _init_hash_function(self, hash_function, args):
        instance = hash_function(*args)
        instance._initialize_registers()
        return instance
        
    def _get_rand_message_and_state(self, hash_function, args):
        hash_function = self._init_hash_function(hash_function, args)
        message = self.byte_generator.value(self.BLOCK_SIZE)
        # Compute the compress function and then update the internal state.
        new_state = hash_function._process_chunk(message)
        hash_function._update_registers_from(new_state)
        return message, hash_function.state()
        
    def _find_collisions_for(self, hash_function, *args):
        message1, state1 = self._get_rand_message_and_state(hash_function,
                                                            args)
        while True:
            message2, state2 = self._get_rand_message_and_state(hash_function,
                                                                args)
            if state1 == state2:
                break
        return state1, [message1, message2]
    
    def value(self, n, collisions=None, state=None):
        # This is to resume from a given list of collisions.
        collisions = collisions if collisions is not None else [str()]
        state = state if state is not None else list()
        for i in range(n):
            # Find a new collision for current state registers, and then
            # combine the results.
            args = (self.hash_function,) if i == 0 and len(state) == 0\
                   else (self.resumable_hash, state)
            state, new_collisions = self._find_collisions_for(*args)
            collisions = [c1 + c2 for c1 in collisions
                                  for c2 in new_collisions]
        return collisions, state
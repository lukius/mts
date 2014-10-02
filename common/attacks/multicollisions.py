from common.attacks.tools.hash import CollisionGeneratorBase


class MulticollisionGenerator(CollisionGeneratorBase):
    
    # Based on Joux's "Multicollisions in iterated hash functions. Application
    # to cascaded constructions. "
    
    def _get_rand_message_and_state(self, state):
        message = self.byte_generator.value(self.block_size)
        final_state = self._iterate_compress_function(message, state)
        return message, final_state
        
    def _find_collisions_for(self, state):
        message1, state1 = self._get_rand_message_and_state(state)
        while True:
            message2, state2 = self._get_rand_message_and_state(state)
            if state1 == state2:
                break
        return state1, [message1, message2]
    
    def value(self, n, collisions=None, state=None):
        # This is to resume from a given list of collisions.
        collisions = collisions if collisions is not None else [str()]
        state = state if state is not None\
                else self.resumable_hash.initial_state()
        for _ in range(n):
            # Find a new collision for current state registers, and then
            # combine the results.
            state, new_collisions = self._find_collisions_for(state)
            collisions = [c1 + c2 for c1 in collisions
                                  for c2 in new_collisions]
        return collisions, state
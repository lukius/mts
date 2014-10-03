from collections import defaultdict

from common.attacks.tools.hash import CollisionGeneratorBase


class MulticollisionGenerator(CollisionGeneratorBase):
    
    # Based on Joux's "Multicollisions in iterated hash functions. Application
    # to cascaded constructions. "
    
    def _get_rand_message_and_state(self, state):
        message = self.byte_generator.value(self.block_size)
        final_state = self._iterate_compress_function(message, state)
        return message, final_state
        
    def _find_collisions_for(self, initial_state):
        collisions = defaultdict(lambda: list())
        while True:
            message, state = self._get_rand_message_and_state(initial_state)
            collisions[state].append(message)
            if len(collisions[state]) > 1:
                break
        return state, collisions[state]
    
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
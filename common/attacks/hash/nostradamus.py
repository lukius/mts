import random

from common.attacks.tools.hash import CollisionGeneratorBase


class NostradamusAttack(CollisionGeneratorBase):
    
    # Based on Kelsey's & Kohno's "Herding Hash Functions and the
    # Nostradamus Attack"
    
    DEFAULT_K = 10
    
    def __init__(self, md_hash_function, k=None):
        CollisionGeneratorBase.__init__(self, md_hash_function)
        self.k = k if k is not None else self.DEFAULT_K
        self._compute_prediction()
    
    def _get_rand_states(self, count):
        state_size = len(self.resumable_hash.initial_state())
        max_int = 2**self.resumable_hash.register_size() - 1
        return [tuple([random.randint(0, max_int) for _ in range(state_size)])
                for _ in range(count)]
        
    def _find_collision_for(self, state1, state2):
        collisions = dict()
        while True:
            block1 = self.byte_generator.value(self.block_size)
            block2 = self.byte_generator.value(self.block_size)
            final_state1 = self._iterate_compress_function(block1, state1)
            final_state2 = self._iterate_compress_function(block2, state2)
            collisions[final_state2] = block2
            if final_state1 in collisions:
                break
        return final_state1, (block1, collisions[final_state1])       
        
    def _update_diamond(self, states, level):
        new_states = list()
        for i in range(0, len(states), 2):
            new_state, blocks = self._find_collision_for(states[i],
                                                         states[i+1])
            self.diamond.make_transition(level, states[i],
                                         blocks[0], new_state)
            self.diamond.make_transition(level, states[i+1],
                                         blocks[1], new_state)
            new_states.append(new_state)
        return new_states
    
    def _compute_prediction(self):
        # Build the diamond structure dynamically during collision generation.
        self.diamond = Diamond(self.k)
        states = self._get_rand_states(2**self.k)
        for i in range(self.k):
            states = self._update_diamond(states, i)
        self.final_state = states[0]
    
    def prediction(self):
        return self.final_state
    
    def for_prefix(self, prefix):
        # TBC
        return str()
    
    
class Diamond(object):
    
    def __init__(self, size):
        self.size = size
        self.structure = [dict() for _ in range(size)]
        
    def make_transition(self, level, source_state, block, dest_state):
        if level < 0 or level >= self.size:
            raise IndexError('level out of range')
        source_level = self.structure[level]
        source_level[source_state] = (block, dest_state)
        
    def traverse_from(self, initial_state):
        path = str()
        state = initial_state
        for index, level in enumerate(self.structure):
            if state not in self.structure[index]:
                raise RuntimeError('intermediate state not present')
            block, state = level[state]
            path += block
        return path
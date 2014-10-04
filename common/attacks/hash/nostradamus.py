import random

from common.attacks.tools.hash import CollisionGeneratorBase
from common.tools.padders import MDPadder


class NostradamusAttack(CollisionGeneratorBase):
    
    # Based on Kelsey's & Kohno's "Herding Hash Functions and the
    # Nostradamus Attack"
    
    DEFAULT_K = 10
    
    def __init__(self, md_hash_function, prediction_length, k=None):
        CollisionGeneratorBase.__init__(self, md_hash_function)
        self.k = k if k is not None else self.DEFAULT_K
        self.prediction_length = prediction_length
        self._compute_prediction_hash()
    
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
    
    def _build_diamond(self):
        # Build the diamond structure dynamically during collision generation.
        self.diamond = Diamond(self.k)
        states = self._get_rand_states(2**self.k)
        for i in range(self.k):
            states = self._update_diamond(states, i)
        # states will only have one state, which is the final state of the
        # structure.
        return states[0]
    
    def _compress_padding_block_from(self, state):
        dummy_message = 'X'*self.prediction_length
        padded_message = MDPadder(dummy_message,
                                  self.hash_function.endianness()).value()
        padding_block = padded_message[-self.block_size:]
        return self._iterate_compress_function(padding_block, state)

    def _compute_prediction_hash(self):
        final_diamond_state = self._build_diamond()
        # The actual hash has to take into account the length of the prediction
        # message.
        end_state = self._compress_padding_block_from(final_diamond_state)
        hash_function = self._init_hash_function(end_state)
        self.prediction_hash = hash_function._compute_value()
    
    def _find_link_to_diamond(self, message):
        initial_state = self._iterate_compress_function(message)
        while True:
            link = self.byte_generator.value(self.block_size)
            link_final_state = self._iterate_compress_function(link,
                                                               initial_state)
            if link_final_state in self.diamond:
                break      
        return link_final_state, link    
    
    def prediction(self):
        return self.prediction_hash
    
    def for_prefix(self, prefix):
        prefix_length = len(prefix)
        # Add dummy glue blocks in order to complete the desired prediction
        # length. The amount of glue blocks is found by subtracting from 
        # the prediction block length the prefix block length, the linking
        # block into the diamond and the diamond traversal blocks.
        glue_length = self.prediction_length - prefix_length -\
                      self.block_size*(self.k+1)
        if glue_length < 0:
            raise RuntimeError('invalid prefix length')
        message = prefix + 'X'*glue_length
        state, link = self._find_link_to_diamond(message)
        diamond_path = self.diamond.traverse_from(state)
        return message + link + diamond_path

    
class Diamond(object):
    
    def __init__(self, size):
        self.size = size
        self.structure = [dict() for _ in range(size)]
        
    def __contains__(self, state):
        return state in self.structure[0]
        
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
from common.attacks.tools.hash import ResumableMDHash
from common.tools.misc import RandomByteGenerator, Concatenation
# TODO: move to tools
from common.ciphers.block.string import BlockString


class SecondPreimageAttack(object):
    
    # Based on Kelsey's & Schneier's "Second Preimages on n-bit Hash
    # Functions for Much Less than 2**n Work" 
    
    def __init__(self, md_hash_function):
        self.resumable_hash = ResumableMDHash(md_hash_function).value()
        
    # TODO: refactor
    def _init_hash_function(self, initial_state):
        instance = self.resumable_hash(initial_state)
        instance._initialize_registers()
        return instance
    
    def _compute_state_map_from(self, block_string, initial_state):
        state_map = dict()
        hash_function = self._init_hash_function(initial_state)
        for index, block in enumerate(block_string):
            new_state = hash_function._process_chunk(block)
            hash_function._update_registers_from(new_state)
            current_state = hash_function.state()
            state_map[tuple(current_state)] = index
        return state_map
    
    def _compute_final_state(self, blocks, initial_state):
        hash_function = self._init_hash_function(initial_state)
        for block in blocks:
            new_state = hash_function._process_chunk(block)
            hash_function._update_registers_from(new_state)
        return hash_function.state()    
        
    def _build_state_map_for(self, block_string):
        initial_state = self.resumable_hash.initial_state()
        return self._compute_state_map_from(block_string, initial_state)
    
    def _find_block_matching(self, state_map, exp_message_state, k):
        byte_generator = RandomByteGenerator()
        while True:
            block = byte_generator.value(self.block_size)
            block_final_state = self._compute_final_state([block],
                                                          exp_message_state)
            if tuple(block_final_state) in state_map and\
               state_map[block_final_state] > k:
                break      
        return state_map[block_final_state], block
        
    def value(self, message, k):
        block_string = BlockString(message, self.resumable_hash.block_size())
        # Compute the expandable message for this k.
        exp_message_generator = ExpandableMessageGenerator(self.resumable_hash)
        exp_message_state, exp_message = exp_message_generator.value(k)
        # Build a mapping from intermediate states to block indices.
        state_map = self._build_state_map_for(block_string)
        i, block = self._find_block_matching(state_map, exp_message_state, k)
        # Now, generate a message having i blocks from the expandable message.
        # ...
    
    
class ExpandableMessageGenerator(object):
    
    def __init__(self, resumable_hash_function):
        self.resumable_hash = resumable_hash_function
        self.block_size = self.resumable_hash.block_size()
        
    def _get_dummy_blocks(self, length):
        return ['X'*self.block_size]*length
    
    def _init_hash_function(self, initial_state):
        instance = self.resumable_hash(initial_state)
        instance._initialize_registers()
        return instance
    
    def _compute_final_state(self, blocks, initial_state):
        hash_function = self._init_hash_function(initial_state)
        for block in blocks:
            new_state = hash_function._process_chunk(block)
            hash_function._update_registers_from(new_state)
        return hash_function.state()
    
    def _find_colliding_block(self, prefix, initial_state):
        byte_generator = RandomByteGenerator()
        prefix_state = self._compute_final_state(prefix, initial_state)
        while True:
            last_block = byte_generator.value(self.block_size)
            block = byte_generator.value(self.block_size)
            last_block_final_state = self._compute_final_state([last_block],
                                                               prefix_state)
            block_final_state = self._compute_final_state([block],
                                                          initial_state)
            if last_block_final_state == block_final_state:
                break
        return block_final_state, (block, last_block)
    
    def _find_colliding_messages_for(self, length, initial_state):
        prefix = self._get_dummy_blocks(length)
        final_state, blocks = self._find_colliding_block(prefix, initial_state)
        message = Concatenation(prefix+[blocks[1]]).value()
        return final_state, (blocks[0], message)
        
    def value(self, k):
        expandable_message = list()
        state = self.resumable_hash.initial_state()
        for i in range(k):
            state, messages = self._find_colliding_messages_for(2**(k-i-1),
                                                                state)
            expandable_message.append(messages)
        return state, expandable_message
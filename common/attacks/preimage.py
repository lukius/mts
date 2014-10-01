from common.attacks.tools.hash import ResumableMDHash
from common.tools.misc import RandomByteGenerator, Concatenation


class SecondPreimageAttack(object):
    
    # Based on Kelsey's & Schneier's "Second Preimages on n-bit Hash
    # Functions for Much Less than 2**n Work" 
    
    def __init__(self, md_hash_function):
        self.hash_function = md_hash_function
        
    def value(self, message):
        # TBC
        pass
    
    
class ExpandableMessageGenerator(object):
    
    BLOCK_SIZE = 64
    
    def __init__(self, hash_function):
        self.hash_function = hash_function
        self.resumable_hash = ResumableMDHash(hash_function).value()
        
    def _get_dummy_blocks(self, length):
        return ['X'*self.BLOCK_SIZE]*length
    
    def _init_hash_function(self, initial_state):
        if initial_state is None:
            instance = self.hash_function()
        else:
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
            last_block = byte_generator.value(self.BLOCK_SIZE)
            block = byte_generator.value(self.BLOCK_SIZE)
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
        expandable_message = dict()
        state = None
        for i in range(k):
            state, messages = self._find_colliding_messages_for(2**(k-i-1),
                                                                state)
            expandable_message[i] = messages
        return expandable_message
from common.attacks.tools.hash import CollisionGeneratorBase
from common.tools.blockstring import BlockString


class SecondPreimageAttack(CollisionGeneratorBase):
    
    # Based on Kelsey's & Schneier's "Second Preimages on n-bit Hash
    # Functions for Much Less than 2**n Work" 
    
    def __init__(self, md_hash_function):
        CollisionGeneratorBase.__init__(self, md_hash_function)
        self.msg_generator = ExpandableMessageGenerator(md_hash_function)
        
    def _build_state_map_for(self, block_string):
        def block_i_state(i, block, hash_function):
            current_state = hash_function.state()
            state_map[tuple(current_state)] = i

        state_map = dict()
        initial_state = self.resumable_hash.initial_state()
        self._iterate_compress_function(block_string, initial_state,
                                        block_callback=block_i_state)
        return state_map
    
    def _find_link(self, state_map, exp_msg_state, k):
        while True:
            link = self.byte_generator.value(self.block_size)
            link_final_state = self._iterate_compress_function(link,
                                                               exp_msg_state)
            link_final_state = tuple(link_final_state)
            if link_final_state in state_map and\
               state_map[link_final_state] > k:
                break      
        return state_map[link_final_state], link
    
    def _build_prefix(self, expandable_message, j, k):
        prefix = str()
        for i, messages in enumerate(expandable_message):
            length = 2**(k-i-1)
            if j - length > 0:
                prefix += messages[1]
                j -= length
            else:
                prefix += messages[0]
                j -= 1
        return prefix
        
    def value(self, message, k):
        block_string = BlockString(message, self.resumable_hash.block_size())
        # Compute the expandable message for this k.
        exp_message_state, exp_message = self.msg_generator.value(k)
        # Build a mapping from intermediate states to block indices.
        state_map = self._build_state_map_for(block_string)
        j, link = self._find_link(state_map, exp_message_state, k)
        # Now, generate a prefix having j blocks from the expandable message.
        prefix = self._build_prefix(exp_message, j, k)
        # ...and remove first j+1 blocks from the original message.
        block_string.remove_blocks_until(j+1)
        return prefix + link + block_string.bytes()

    
class ExpandableMessageGenerator(CollisionGeneratorBase):
    
    def _get_dummy_blocks(self, length):
        return 'X'*self.block_size*length
    
    def _find_colliding_block(self, prefix, initial_state):
        prefix_state = self._iterate_compress_function(prefix, initial_state)
        while True:
            last_block = self.byte_generator.value(self.block_size)
            single_block = self.byte_generator.value(self.block_size)
            state1 = self._iterate_compress_function(last_block, prefix_state)
            state2 = self._iterate_compress_function(single_block,
                                                     initial_state)
            if state1 == state2:
                break
        return state1, (single_block, last_block)
    
    def _find_colliding_messages_for(self, length, initial_state):
        prefix = self._get_dummy_blocks(length)
        final_state, blocks = self._find_colliding_block(prefix, initial_state)
        return final_state, (blocks[0], prefix + blocks[1])
        
    def value(self, k):
        expandable_message = list()
        state = self.resumable_hash.initial_state()
        for i in range(k):
            state, messages = self._find_colliding_messages_for(2**(k-i-1),
                                                                state)
            expandable_message.append(messages)
        return state, expandable_message
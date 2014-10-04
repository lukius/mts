from common.attacks.tools.hash import CollisionGeneratorBase
from common.tools.blockstring import BlockString


class SecondPreimageAttack(CollisionGeneratorBase):
    
    # Based on Kelsey's & Schneier's "Second Preimages on n-bit Hash
    # Functions for Much Less than 2**n Work" 
    
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
            if link_final_state in state_map and\
               state_map[link_final_state] > k:
                break      
        return state_map[link_final_state], link
    
    def value(self, message, k):
        block_string = BlockString(message, self.resumable_hash.block_size())
        # Compute the expandable message for this k.
        msg_generator = ExpandableMessageGenerator(self.hash_function, k)
        exp_message_state = msg_generator.state()
        # Build a mapping from intermediate states to block indices.
        state_map = self._build_state_map_for(block_string)
        # Find a linking block from the expandable message to the original
        # message.
        j, link = self._find_link(state_map, exp_message_state, k)
        # Now, generate a prefix having j blocks from the expandable message.
        prefix = msg_generator.value(j)
        # ...and remove first j+1 blocks from the original message.
        block_string.remove_blocks_until(j+1)
        return prefix + link + block_string.bytes()

    
class ExpandableMessageGenerator(CollisionGeneratorBase):
    
    def __init__(self, hash_function, k):
        CollisionGeneratorBase.__init__(self, hash_function)
        self.k = k
        self._build_expandable_message()
    
    def _get_dummy_blocks(self, length):
        return 'X'*self.block_size*length
    
    def _find_colliding_block(self, prefix, initial_state):
        collisions = dict()
        prefix_state = self._iterate_compress_function(prefix, initial_state)
        while True:
            last_block = self.byte_generator.value(self.block_size)
            single_block = self.byte_generator.value(self.block_size)
            state1 = self._iterate_compress_function(last_block, prefix_state)
            state2 = self._iterate_compress_function(single_block,
                                                     initial_state)
            collisions[state2] = single_block
            if state1 in collisions:
                break
        return state1, (collisions[state1], last_block)
    
    def _find_colliding_messages_for(self, length, initial_state):
        prefix = self._get_dummy_blocks(length)
        final_state, blocks = self._find_colliding_block(prefix, initial_state)
        return final_state, (blocks[0], prefix + blocks[1])
        
    def _build_expandable_message(self):
        self.expandable_message = list()
        state = self.resumable_hash.initial_state()
        for i in range(self.k):
            state, messages = self._find_colliding_messages_for(2**(self.k-i-1),
                                                                state)
            self.expandable_message.append(messages)
        self.end_state = state
        
    def state(self):
        return self.end_state
            
    def value(self, length):
        prefix = str()
        for i, messages in enumerate(self.expandable_message):
            current_length = 2**(self.k-i-1)
            if length - current_length > 0:
                prefix += messages[1]
                length -= current_length
            else:
                prefix += messages[0]
                length -= 1
        return prefix
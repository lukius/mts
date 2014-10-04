from common.tools.blockstring import BlockString
from common.tools.misc import RandomByteGenerator


class ResumableMDHash(object):
    
    def __init__(self, hash_function_class):
        self.hash_function_class = hash_function_class
        
    def value(self):
        resumable_hash = self
        
        class ResumableHash(self.hash_function_class):
            
            def __init__(self, registers):
                resumable_hash.hash_function_class.__init__(self)
                self.custom_registers = registers
                
            def _initialize_registers(self):
                self.registers = list(self.custom_registers)
                
            def _pad_message(self, message):
                # Treat incoming messages as if they were already padded.
                return message
            
        return ResumableHash
    

class CollisionGeneratorBase(object):

    def __init__(self, hash_function):
        self.hash_function = hash_function
        self.resumable_hash = ResumableMDHash(hash_function).value()
        self.block_size = self.resumable_hash.block_size()
        self.byte_generator = RandomByteGenerator()

    def _init_hash_function(self, initial_state):
        instance = self.resumable_hash(initial_state)
        instance._initialize_registers()
        return instance
    
    def _iterate_compress_function(self, message, initial_state=None,
                                   block_callback=None):
        if not isinstance(message, BlockString):
            message = BlockString(message, self.block_size)
        if initial_state is None:
            initial_state = self.hash_function.initial_state()
        hash_function = self._init_hash_function(initial_state)
        for index, block in enumerate(message):
            new_state = hash_function._process_chunk(block)
            hash_function._update_registers_from(new_state)
            if block_callback is not None:
                block_callback(index, block, hash_function)
        return tuple(hash_function.state())    
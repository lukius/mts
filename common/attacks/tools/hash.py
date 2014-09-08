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
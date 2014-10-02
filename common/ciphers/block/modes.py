from common.tools.blockstring import BlockString
from common.tools.padders import PKCS7Padder, PKCS7Unpadder
from common.tools.xor import ByteXOR


class BlockCipherMode(object):
    
    DEFAULT_BLOCK_SIZE = 16

    @classmethod                  
    def name(cls):
        return cls.__name__

    def __init__(self, block_size=None):
        self.block_size = self.DEFAULT_BLOCK_SIZE if block_size is None\
                          else block_size 
    
    def _pad(self, string):
        return PKCS7Padder(string).value(self.block_size)

    def _unpad_if_needed(self, index, block):
        if self.block_string.is_last_block_index(index):
            block = PKCS7Unpadder(block).value()
        return block    
    
    def _iterate_blocks_with(self, block_string, cipher, callback):
        self.cipher = cipher
        self.block_string = block_string
        result = BlockString(block_size=self.block_size)
        return reduce(lambda _result, block: _result + callback(*block),
                      enumerate(self.block_string), result)

    def _block_encryption_callback(self, message, cipher):
        raise NotImplementedError
    
    def _block_decryption_callback(self, message, cipher):
        raise NotImplementedError

    def encrypt_with_cipher(self, plaintext, cipher):
        if type(plaintext) != BlockString:
            plaintext = BlockString(plaintext, self.block_size)
        plaintext = self._pad(plaintext)
        return self._iterate_blocks_with(plaintext, cipher,
                                         self._block_encryption_callback)
    
    def decrypt_with_cipher(self, ciphertext, cipher):
        if type(ciphertext) != BlockString:
            ciphertext = BlockString(ciphertext, self.block_size)
        return self._iterate_blocks_with(ciphertext, cipher,
                                         self._block_decryption_callback)


class ECB(BlockCipherMode):
    
    def _block_encryption_callback(self, index, block):
        return self.cipher.encrypt_block(block)
    
    def _block_decryption_callback(self, index, block):
        plaintext_block = self.cipher.decrypt_block(block)
        plaintext_block = self._unpad_if_needed(index, plaintext_block)
        return plaintext_block    
    

class CBC(BlockCipherMode):
    
    def __init__(self, iv, block_size=None):
        BlockCipherMode.__init__(self, block_size)
        self.iv = iv

    def _xor(self, string1, string2):
        return ByteXOR(string1, string2).value()

    def _block_encryption_callback(self, index, block):
        if index == 0:
            self.last_ciphertext_block = self.iv 
        xor_block = self._xor(block, self.last_ciphertext_block)
        ciphertext_block = self.cipher.encrypt_block(xor_block)        
        self.last_ciphertext_block = ciphertext_block
        return ciphertext_block
    
    def _block_decryption_callback(self, index, block):
        if index == 0:
            self.last_ciphertext_block = self.iv
        decrypted_block = self.cipher.decrypt_block(block)
        plaintext_block = self._xor(decrypted_block,
                                    self.last_ciphertext_block)
        plaintext_block = self._unpad_if_needed(index, plaintext_block)
        self.last_ciphertext_block = block
        return plaintext_block
        
        
class CTR(BlockCipherMode):
    
    def __init__(self, counter=None, nonce=None, block_size=None):
        from counter import DefaultCounter, NonceBasedCounter
        BlockCipherMode.__init__(self, block_size)
        if nonce is not None:
            counter = NonceBasedCounter(nonce, block_size)
        self.counter = counter if counter is not None\
                       else DefaultCounter(block_size)
                       
    def _pad(self, plaintext):
        # CTR mode does not need padding.
        return plaintext
                       
    def _xor(self, key, block):
        block_length = len(block)
        return ByteXOR(block, key[:block_length]).value()
    
    def _block_callback(self, index, block):
        key_argument = self.counter.count(index)
        key = self.cipher.encrypt_block(key_argument)
        return self._xor(key, block)
                       
    def _block_encryption_callback(self, index, block):
        return self._block_callback(index, block)
    
    def _block_decryption_callback(self, index, block):
        return self._block_callback(index, block)
    
    
class RandomAccessCTR(CTR):
    
    def __init__(self, *args, **kwargs):
        CTR.__init__(self, *args, **kwargs)
        self.keystream = str()
        
    def get_keystream(self):
        return self.keystream
        
    def _xor(self, key, block):
        self.keystream += key
        return CTR._xor(self, key, block)
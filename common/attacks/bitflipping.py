from common.ciphers.block.aes import AES
from common.tools.xor import ByteXOR


class BitFlippingAttack(object):
    
    TARGET_STRING = ';admin=true'
    TARGET_BLOCK_INDEX = 3
    
    def __init__(self, profile_generator, block_size):
        self.profile_generator = profile_generator
        self.block_size = block_size
        
    def get_string(self):
        raise NotImplementedError

    def value(self):
        string = self.get_string()
        encrypted_profile = self.profile_generator.profile_for(string)
        # XOR our ';admin=true' string with our plaintext and the ciphered block
        # in order to inject it in the ciphertext.
        target_block = encrypted_profile.get_block(self.TARGET_BLOCK_INDEX)
        tampered_block = ByteXOR('X'*len(self.TARGET_STRING),
                                 self.TARGET_STRING, target_block).value()
        encrypted_profile.replace_block(self.TARGET_BLOCK_INDEX, tampered_block)
        return encrypted_profile
    
    
class UserProfileParser(object):

    def __init__(self, key, decryption_mode):
        self.cipher = AES(key)
        self.mode = decryption_mode
        
    def _unquote(self, text):
        text = text.replace('%3B', ';')
        text = text.replace('%3D', '=')
        return text        

    def parse(self, encrypted_profile):
        profile_string = self.cipher.decrypt(encrypted_profile,
                                             mode=self.mode)
        return self._unquote(profile_string.bytes())
    
    
class UserProfileGenerator(object):
    
    PREFIX = 'comment1=cooking%20MCs;userdata='
    SUFFIX = ';comment2=%20like%20a%20pound%20of%20bacon'
    
    def __init__(self, key, encryption_mode):
        self.cipher = AES(key)
        self.mode = encryption_mode
        
    def _quote(self, text):
        text = text.replace(';', '%3B')
        text = text.replace('=', '%3D')
        return text
    
    def profile_for(self, user_data):
        plaintext = '%s%s%s' % (self.PREFIX, user_data, self.SUFFIX)
        plaintext = self._quote(plaintext)
        return self.cipher.encrypt(plaintext, mode=self.mode)
    
    
class InvalidProfileException(Exception):
    
    def __init__(self, profile):
        Exception.__init__(self)
        self.profile = profile
        
    def get_profile(self):
        return self.profile
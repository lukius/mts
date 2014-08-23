from collections import defaultdict 

from common.challenge import MatasanoChallenge
from common.tools import RandomByteGenerator
from common.xor import ByteXOR
from common.ciphers.block.cipher import AES
from common.ciphers.block.modes import CBC


class UserProfileParser(object):

    def __init__(self, key, iv):
        self.cipher = AES(key)
        self.iv = iv
        
    def _unquote(self, text):
        text = text.replace('%3B', ';')
        text = text.replace('%3D', '=')
        return text        

    def _parse(self, profile):
        tuples = profile.split(';')
        profile = defaultdict(lambda: None)
        profile.update(map(lambda item: item.split('='), tuples))
        return profile
    
    def parse(self, encrypted_profile):
        profile_string = self.cipher.decrypt(encrypted_profile,
                                             mode=CBC(self.iv))
        profile_string = self._unquote(profile_string.bytes())
        return self._parse(profile_string)
    
    
class UserProfileGenerator(object):
    
    PREFIX = 'comment1=cooking%20MCs;userdata='
    SUFFIX = ';comment2=%20like%20a%20pound%20of%20bacon'
    
    def __init__(self, key, iv):
        self.cipher = AES(key)
        self.iv = iv
        
    def _quote(self, text):
        text = text.replace(';', '%3B')
        text = text.replace('=', '%3D')
        return text
    
    def profile_for(self, user_data):
        plaintext = '%s%s%s' % (self.PREFIX, user_data, self.SUFFIX)
        plaintext = self._quote(plaintext)
        return self.cipher.encrypt(plaintext, mode=CBC(self.iv))    
    

class CBCBitFlippingAttack(object):
    
    TARGET_STRING = ';admin=true'
    TARGET_BLOCK_INDEX = 3
    
    def __init__(self, profile_generator, block_size):
        self.profile_generator = profile_generator
        self.block_size = block_size
        
    def value(self):
        # Generate profile using enough data to make two extra blocks.
        # First 10 bytes complete the previous block. We assume knowledge
        # of the prefix introduced by the profile generator.
        string = 'X'*(10 + 2*self.block_size)
        encrypted_profile = self.profile_generator.profile_for(string)
        # Now, XOR the first new block with the target value and the actual
        # plaintext value (we know this since we supplied it). 
        target_block = encrypted_profile.get_block(self.TARGET_BLOCK_INDEX)
        string = ByteXOR('X'*len(self.TARGET_STRING), self.TARGET_STRING).\
                 value()
        tampered_block = ByteXOR(target_block, string).value()
        # This will propagate to the next block during decryption. The target
        # value will magically appear instead of the original plaintext value.
        encrypted_profile.replace_block(self.TARGET_BLOCK_INDEX, tampered_block)
        return encrypted_profile


class Set2Challenge8(MatasanoChallenge):

    BLOCK_SIZE = 16

    def expected_value(self):
        return 'true'
    
    def value(self):
        secret_key = RandomByteGenerator().value(self.BLOCK_SIZE)
        secret_iv = RandomByteGenerator().value(self.BLOCK_SIZE)
        profile_generator = UserProfileGenerator(secret_key, secret_iv)
        attack = CBCBitFlippingAttack(profile_generator, self.BLOCK_SIZE)
        encrypted_profile = attack.value()
        profile = UserProfileParser(secret_key, secret_iv).\
                  parse(encrypted_profile)
        return profile['admin']
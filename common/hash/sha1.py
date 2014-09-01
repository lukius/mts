import struct

from common.converters import IntToBytes
from common.hash import HashFunction


class SHA1(HashFunction):
    # Based on Wikipedia pseudocode.
    
    H0 = 0x67452301
    H1 = 0xefcdab89
    H2 = 0x98badcfe
    H3 = 0x10325476
    H4 = 0xc3d2e1f0
    
    def _initialize_values(self):
        self.h0 = self.H0
        self.h1 = self.H1
        self.h2 = self.H2
        self.h3 = self.H3
        self.h4 = self.H4
        
    def _pad_message(self, message):
        bit_length = len(message)*8
        
        # Append bit 1 to the message.
        message += '\x80'
        
        # Add zeros; bit length should be equal to 448 mod 512.
        zero_bytes = (448 - bit_length - 8) % 512
        zero_bits = zero_bytes/8
        message += '\0' * zero_bits
        
        # Append bit length as a 64-bit big-endian integer.
        message += struct.pack('>Q', bit_length)
        
        return message        
    
    def _rotate_left(self, integer, count):
        return ((integer << count) |\
                (integer >> (32 - count))) & 0xffffffff

    def _get_big_endian_words_from(self, chunk):
        words = list()
        for i in range(0, len(chunk), 4):
            word = struct.unpack('>I', chunk[i:i+4])[0]
            words.append(word)
        return words
    
    def _extend_words(self, words):
        for i in range(16, 80):
            new_word = self._rotate_left(words[i-3] ^ words[i-8] ^\
                                         words[i-14] ^ words[i-16], 1)
            words.append(new_word)
        return words

    def _process_chunk(self, chunk):
        w = self._get_big_endian_words_from(chunk)
        w = self._extend_words(w)

        a = self.h0
        b = self.h1
        c = self.h2
        d = self.h3
        e = self.h4
    
        for i in range(80):
            if 0 <= i <= 19:
                f = d ^ (b & (c ^ d))
                k = 0x5a827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ed9eba1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8f1bbcdc
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xca62c1d6
    
            temp = (self._rotate_left(a, 5) + f + e + k + w[i])\
                   & 0xffffffff
            e = d
            d = c
            c = self._rotate_left(b, 30)
            b = a
            a = temp

        return a, b, c, d, e
    
    def _compute_value(self):
        return (self.h0<<128) + (self.h1<<96) + (self.h2<<64) +\
               (self.h3<<32) + self.h4

    def hash(self, message):
        self._initialize_values()
        message = self._pad_message(message)
        
        # Process 512-bit chunks.
        for i in range(0, len(message), 64):
            a, b, c, d, e = self._process_chunk(message[i:i+64])
            
            # Add chunk hash to result.
            self.h0 = (self.h0 + a) & 0xffffffff
            self.h1 = (self.h1 + b) & 0xffffffff 
            self.h2 = (self.h2 + c) & 0xffffffff
            self.h3 = (self.h3 + d) & 0xffffffff
            self.h4 = (self.h4 + e) & 0xffffffff            
        
        hash_value = self._compute_value()
        return IntToBytes(hash_value).value()
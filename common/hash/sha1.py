import struct

from common.converters import IntToBytes
from common.hash import HashFunction
from common.int import FixedSizeInteger
from common.padders import SHA1Padder


class SHA1(HashFunction):
    # Based on Wikipedia pseudocode.
    
    H0 = FixedSizeInteger(0x67452301)
    H1 = FixedSizeInteger(0xefcdab89)
    H2 = FixedSizeInteger(0x98badcfe)
    H3 = FixedSizeInteger(0x10325476)
    H4 = FixedSizeInteger(0xc3d2e1f0)
    
    def _initialize_values(self):
        self.h0 = self.H0
        self.h1 = self.H1
        self.h2 = self.H2
        self.h3 = self.H3
        self.h4 = self.H4
        
    def _pad_message(self, message):
        return SHA1Padder(message).value()
    
    def _rotate_left(self, integer, count):
        return ((integer << count) | (integer >> (32 - count))) & 0xffffffff

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

        a = int(self.h0)
        b = int(self.h1)
        c = int(self.h2)
        d = int(self.h3)
        e = int(self.h4)
    
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
    
            temp = FixedSizeInteger(self._rotate_left(a, 5) + f + e + k + w[i])

            e = d
            d = c
            c = self._rotate_left(b, 30)
            b = a
            a = int(temp)

        return a, b, c, d, e
    
    def _compute_value(self):
        return (int(self.h0)<<128) + (int(self.h1)<<96) +\
               (int(self.h2)<<64) + (int(self.h3)<<32) + int(self.h4)

    def hash(self, message):
        self._initialize_values()
        message = self._pad_message(message)
        
        # Process 512-bit chunks.
        for i in range(0, len(message), 64):
            a, b, c, d, e = self._process_chunk(message[i:i+64])
            
            # Add chunk hash to result.
            self.h0 += a
            self.h1 += b 
            self.h2 += c
            self.h3 += d
            self.h4 += e            
        
        hash_value = self._compute_value()
        return IntToBytes(hash_value).value()
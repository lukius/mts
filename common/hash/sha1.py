from common.tools.endianness import BigEndian
from common.hash.md import MDHashFunction


class SHA1(MDHashFunction):
    # Based on Wikipedia pseudocode.
    
    H0 = 0x67452301
    H1 = 0xefcdab89
    H2 = 0x98badcfe
    H3 = 0x10325476
    H4 = 0xc3d2e1f0
    
    
    @classmethod
    def get_OID(cls):
        return '\x06\x05\x2b\x0e\x03\x02\x1a'
    
    @classmethod
    def endianness(cls):
        return BigEndian    
    
    def _initialize_registers(self):
        self.registers = [self.H0, self.H1, self.H2, self.H3, self.H4]
    
    def _extend_words(self, words):
        for i in range(16, 80):
            new_word = self._rotate_left(words[i-3] ^ words[i-8] ^\
                                         words[i-14] ^ words[i-16], 1)
            words.append(new_word)
        return words
    
    def _compute_temp_from(self, a, e, f, k, x):
        sum1 = self._capped_sum(self._rotate_left(a, 5), f)
        sum2 = self._capped_sum(sum1, e)
        sum3 = self._capped_sum(sum2, k)
        return self._capped_sum(sum3, x)

    def _process_chunk(self, chunk):
        w = self._get_words_from(chunk)
        w = self._extend_words(w)

        a, b, c, d, e = self.registers
    
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
    
            temp = self._compute_temp_from(a, e, f, k, w[i])

            e = d
            d = c
            c = self._rotate_left(b, 30)
            b = a
            a = temp

        return a, b, c, d, e
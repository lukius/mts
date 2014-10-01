from common.tools.endianness import LittleEndian
from common.hash.md import MDHashFunction


class MD4(MDHashFunction):
    # Custom implementation of MD4.
    
    A = 0x67452301
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476
    
    @classmethod
    def get_OID(cls):
        return '\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x04'

    @classmethod
    def endianness(cls):
        return LittleEndian
    
    @classmethod
    def initial_state(cls):
        return [cls.A, cls.B, cls.C, cls.D]
    
    def F(self, x, y, z):
        return (x & y) | (self._not(x) & z)
    
    def G(self, x, y, z):
        return (x & y) | (x & z) | (y & z)
    
    def H(self, x, y, z):
        return x ^ y ^ z

    def _round_operation(self, a, b, c, d, x, s, func, z=0):
        sum1 = self._capped_sum(a, func(b, c, d))
        sum2 = self._capped_sum(sum1, x)
        sum3 = self._capped_sum(sum2, z)
        return self._rotate_left(sum3, s)
               
    def _round_1(self, words, a, b, c, d):
        a = self._round_operation(a, b, c, d, words[0], 3, self.F)
        d = self._round_operation(d, a, b, c, words[1], 7, self.F)
        c = self._round_operation(c, d, a, b, words[2], 11, self.F)
        b = self._round_operation(b, c, d, a, words[3], 19, self.F)
        a = self._round_operation(a, b, c, d, words[4], 3, self.F)
        d = self._round_operation(d, a, b, c, words[5], 7, self.F)
        c = self._round_operation(c, d, a, b, words[6], 11, self.F)
        b = self._round_operation(b, c, d, a, words[7], 19, self.F)
        a = self._round_operation(a, b, c, d, words[8], 3, self.F)
        d = self._round_operation(d, a, b, c, words[9], 7, self.F)
        c = self._round_operation(c, d, a, b, words[10], 11, self.F)
        b = self._round_operation(b, c, d, a, words[11], 19, self.F)
        a = self._round_operation(a, b, c, d, words[12], 3, self.F)
        d = self._round_operation(d, a, b, c, words[13], 7, self.F)
        c = self._round_operation(c, d, a, b, words[14], 11, self.F)
        b = self._round_operation(b, c, d, a, words[15], 19, self.F)   
        return a, b, c, d
    
    def _round_2(self, words, a, b, c, d):
        z = 0x5a827999
        a = self._round_operation(a, b, c, d, words[0], 3, self.G, z)
        d = self._round_operation(d, a, b, c, words[4], 5, self.G, z)
        c = self._round_operation(c, d, a, b, words[8], 9, self.G, z)
        b = self._round_operation(b, c, d, a, words[12], 13, self.G, z)
        a = self._round_operation(a, b, c, d, words[1], 3, self.G, z)
        d = self._round_operation(d, a, b, c, words[5], 5, self.G, z)
        c = self._round_operation(c, d, a, b, words[9], 9, self.G, z)
        b = self._round_operation(b, c, d, a, words[13], 13, self.G, z)
        a = self._round_operation(a, b, c, d, words[2], 3, self.G, z)
        d = self._round_operation(d, a, b, c, words[6], 5, self.G, z)
        c = self._round_operation(c, d, a, b, words[10], 9, self.G, z)
        b = self._round_operation(b, c, d, a, words[14], 13, self.G, z)
        a = self._round_operation(a, b, c, d, words[3], 3, self.G, z)
        d = self._round_operation(d, a, b, c, words[7], 5, self.G, z)
        c = self._round_operation(c, d, a, b, words[11], 9, self.G, z)
        b = self._round_operation(b, c, d, a, words[15], 13, self.G, z)
        return a, b, c, d
    
    def _round_3(self, words, a, b, c, d):
        z = 0x6ed9eba1
        a = self._round_operation(a, b, c, d, words[0], 3, self.H, z)
        d = self._round_operation(d, a, b, c, words[8], 9, self.H, z)
        c = self._round_operation(c, d, a, b, words[4], 11, self.H, z)
        b = self._round_operation(b, c, d, a, words[12], 15, self.H, z)
        a = self._round_operation(a, b, c, d, words[2], 3, self.H, z)
        d = self._round_operation(d, a, b, c, words[10], 9, self.H, z)
        c = self._round_operation(c, d, a, b, words[6], 11, self.H, z)
        b = self._round_operation(b, c, d, a, words[14], 15, self.H, z)
        a = self._round_operation(a, b, c, d, words[1], 3, self.H, z)
        d = self._round_operation(d, a, b, c, words[9], 9, self.H, z)
        c = self._round_operation(c, d, a, b, words[5], 11, self.H, z)
        b = self._round_operation(b, c, d, a, words[13], 15, self.H, z)
        a = self._round_operation(a, b, c, d, words[3], 3, self.H, z)
        d = self._round_operation(d, a, b, c, words[11], 9, self.H, z)
        c = self._round_operation(c, d, a, b, words[7], 11, self.H, z)
        b = self._round_operation(b, c, d, a, words[15], 15, self.H, z)
        return a, b, c, d
    
    def _process_chunk(self, chunk):
        a, b, c, d = self.registers

        words = self._get_words_from(chunk)
        a, b, c, d = self._round_1(words, a, b, c, d)
        a, b, c, d = self._round_2(words, a, b, c, d)
        a, b, c, d = self._round_3(words, a, b, c, d)
        
        return a, b, c, d
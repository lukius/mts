from common.hash.md4 import MD4


class MD4CollisionGenerator(object):
    
    # Based on "Cryptanalysis of the Hash Functions MD4 and RIPEMD" by
    # Wang et al.
    
    def __init__(self):
        self.md4 = MD4()
        
    def _rotate_right(self, integer, count):
        size = self.md4.register_size()
        mask = self.md4.mask
        return ((integer >> count) | (integer << (size - count))) & mask
    
    def _get_bit(self, integer, index):
        return integer & (1 << index)
    
    def _capped_diff(self, a, b):
        return (a - b) % (1 + self.md4.mask)
    
    def _reverse_round_operation(self, a, b, c, d, x, s, func, z=0):
        sum1 = self._capped_diff(self._rotate_right(x, s), a)
        return self._capped_diff(sum1, func(b, c, d))
    
    def _perform_multi_step_modifications(self, words):
        pass
    
    def _perform_message_modifications(self, words):
        a, b, c, d = self.md4.initial_state()
        F = self.md4.F
        
        # First: perform single-step modifications
        
        # a 1,7 = b 0,7
        a_1 = self.md4._round_operation(a, b, c, d, words[0], 3, F)
        a_1 = a_1 ^ self._get_bit(a_1, 6) ^ self._get_bit(b, 6)
        words[0] = self._reverse_round_operation(a, b, c, d, a_1, 3, F)
        
        # d 1,7 = 0; d 1,8 = a 1,8; d 1,11 = a 1,11
        d_1 = self.md4._round_operation(d, a_1, b, c, words[1], 7, F)
        d_1 = d_1 ^\
               self._get_bit(d_1, 6) ^\
              (self._get_bit(d_1, 7) ^ self._get_bit(a_1, 7)) ^\
              (self._get_bit(d_1, 10) ^ self._get_bit(a_1, 10))
        words[1] = self._reverse_round_operation(d, a_1, b, c, d_1, 7, F)
        
        # c 1,7 = 1, c 1,8 = 1, c 1,11 = 0, c 1,26 = d 1,26
        c_1 = self._round_operation(c, d_1, a_1, b, words[2], 11, F)
        c_1 = c_1 ^\
              (self._get_bit(c_1, 6) ^ (1 << 6)) ^\
              (self._get_bit(c_1, 7) ^ (1 << 7)) ^\
               self._get_bit(c_1, 10) ^\
              (self._get_bit(c_1, 25) ^ self._get_bit(d_1, 25))
        words[2] = self._reverse_round_operation(c, d_1, a_1, b, c_1, 11, F)
        
        # b 1,7 = 1, b 1,8 = 0, b 1,11 = 0, b 1,26 = 0
        b_1 = self._round_operation(b, c_1, d_1, a_1, words[3], 19, F)
        b_1 = b_1 ^\
              (self._get_bit(b_1, 6) ^ (1 << 6)) ^\
               self._get_bit(b_1, 7) ^\
               self._get_bit(b_1, 10) ^\
               self._get_bit(b_1, 25)
        words[3] = self._reverse_round_operation(b, c_1, d_1, a_1, b_1, 19, F)
        
        # a 2,8 = 1, a 2,11 = 1, a 2,26 = 0, a 2,14 = b 1,14
        a_2 = self._round_operation(a_1, b_1, c_1, d_1, words[4], 3, F)
        a_2 = a_2 ^\
              (self._get_bit(a_2, 7) ^ (1 << 7)) ^\
              (self._get_bit(a_2, 10) ^ (1 << 10)) ^\
               self._get_bit(a_2, 25) ^\
              (self._get_bit(a_2, 13) ^ self._get_bit(b_1, 13))
        words[4] = self._reverse_round_operation(a_1, b_1, c_1, d_1, a_2, 3, F)
        
        # d 2,14 = 0, d 2,19 = a 2,19 , d 2,20 = a 2,20 ,
        # d 2,21 = a 2,21 , d 2,22 = a 2,22 , d 2,26 = 1
        d_2 = self._round_operation(d_1, a_2, b_1, c_1, words[5], 7, F)
        d_2 = d_2 ^\
               self._get_bit(d_2, 13) ^\
              (self._get_bit(d_2, 18) ^ self._get_bit(a_2, 18)) ^\
              (self._get_bit(d_2, 19) ^ self._get_bit(a_2, 19)) ^\
              (self._get_bit(d_2, 20) ^ self._get_bit(a_2, 20)) ^\
              (self._get_bit(d_2, 21) ^ self._get_bit(a_2, 21)) ^\
              (self._get_bit(d_2, 25) ^ (1 << 25))
        words[5] = self._reverse_round_operation(d_1, a_2, b_1, c_1, d_2, 7, F)
        
        # c 2,13 = d 2,13 , c 2,14 = 0, c 2,15 = d 2,15 ,
        # c 2,19 = 0, c 2,20 = 0, c 2,21 = 1, c 2,22 = 0
        c_2 = self._round_operation(c_1, d_2, a_2, b_1, words[6], 11, F)
        c_2 = c_2 ^\
              (self._get_bit(c_2, 12) ^ self._get_bit(d_2, 12)) ^\
               self._get_bit(c_2, 13) ^\
              (self._get_bit(c_2, 14) ^ self._get_bit(d_2, 14)) ^\
               self._get_bit(c_2, 18) ^\
               self._get_bit(c_2, 19) ^\
              (self._get_bit(c_2, 20) ^ (1 << 20)) ^\
               self._get_bit(c_2, 21)
        words[6] = self._reverse_round_operation(c_1, d_2, a_2, b_1, c_2, 11, F)
        
        # b 2,13 = 1, b 2,14 = 1, b 2,15 = 0, b 2,17 = c 2,17 ,
        # b 2,19 = 0, b 2,20 = 0, b 2,21 = 0, b 2,22 = 0
        b_2 = self._round_operation(b_1, c_2, d_2, a_2, words[7], 19, F)
        b_2 = b_2 ^\
              (self._get_bit(b_2, 12) ^ (1 << 12)) ^\
              (self._get_bit(b_2, 13) ^ (1 << 13)) ^\
               self._get_bit(b_2, 14) ^\
              (self._get_bit(b_2, 16) ^ self._get_bit(c_2, 16)) ^\
               self._get_bit(b_2, 18) ^\
               self._get_bit(b_2, 19) ^\
               self._get_bit(b_2, 20) ^\
               self._get_bit(b_2, 21)
        words[7] = self._reverse_round_operation(b_1, c_2, d_2, a_2, b_2, 19, F)
        
        # a 3,13 = 1, a 3,14 = 1, a 3,15 = 1, a 3,17 = 0,
        # a 3,19 = 0, a 3,20 = 0, a 3,21 = 0, a 3,23 = b 2,23,
        # a 3,22 = 1, a 3,26 = b 2,26
        a_3 = self._round_operation(a_2, b_2, c_2, d_2, words[8], 3, F)
        a_3 = a_3 ^\
              (self._get_bit(a_3, 12) ^ (1 << 12)) ^\
              (self._get_bit(a_3, 13) ^ (1 << 13)) ^\
              (self._get_bit(a_3, 14) ^ (1 << 14)) ^\
               self._get_bit(a_3, 16) ^\
               self._get_bit(a_3, 18) ^\
               self._get_bit(a_3, 19) ^\
               self._get_bit(a_3, 20) ^\
              (self._get_bit(a_3, 22) ^ self._get_bit(b_2, 22)) ^\
              (self._get_bit(a_3, 21) ^ (1 << 21)) ^\
              (self._get_bit(a_3, 25) ^ self._get_bit(b_2, 25))
        words[8] = self._reverse_round_operation(a_2, b_2, c_2, d_2, a_3, 3, F)
        
        # d 3,13 = 1, d 3,14 = 1, d 3,15 = 1, d 3,17 = 0,
        # d 3,20 = 0, d 3,21 = 1, d 3,22 = 1, d 3,23 = 0,
        # d 3,26 = 1, d 3,30 = a 3,30
        d_3 = self._round_operation(d_2, a_3, b_2, c_2, words[9], 7, F)
        d_3 = d_3 ^\
              (self._get_bit(d_3, 12) ^ (1 << 12)) ^\
              (self._get_bit(d_3, 13) ^ (1 << 13)) ^\
              (self._get_bit(d_3, 14) ^ (1 << 14)) ^\
               self._get_bit(d_3, 16) ^\
               self._get_bit(d_3, 19) ^\
              (self._get_bit(d_3, 20) ^ (1 << 20)) ^\
              (self._get_bit(d_3, 21) ^ (1 << 21)) ^\
               self._get_bit(d_3, 22) ^\
              (self._get_bit(d_3, 25) ^ (1 << 25)) ^\
              (self._get_bit(d_3, 29) ^ self._get_bit(a_3, 29))
        words[9] = self._reverse_round_operation(d_2, a_3, b_2, c_2, d_3, 7, F)
        
        # c 3,17 = 1, c 3,20 = 0, c 3,21 = 0, c 3,22 = 0,
        # c 3,23 = 0, c 3,26 = 0, c 3,30 = 1, c 3,32 = d 3,32
        c_3 = self._round_operation(c_2, d_3, a_3, b_2, words[10], 11, F)
        c_3 = c_3 ^\
              (self._get_bit(c_3, 16) ^ (1 << 16)) ^\
              (self._get_bit(c_3, 19)) ^\
              (self._get_bit(c_3, 20)) ^\
               self._get_bit(c_3, 21) ^\
               self._get_bit(c_3, 22) ^\
              (self._get_bit(c_3, 25)) ^\
              (self._get_bit(c_3, 29) ^ (1 << 29)) ^\
              (self._get_bit(c_3, 31) ^ self._get_bit(d_3, 31))
        words[10] = self._reverse_round_operation(c_2, d_3, a_3, b_2, c_3, 11, F)
        
        # b 3,20 = 0, b 3,21 = 1, b 3,22 = 1, b 3,23 = c 3,23,
        # b 3,26 = 1, b 3,30 = 0, b 3,32 = 0
        b_3 = self._round_operation(b_2, c_3, d_3, a_3, words[11], 19, F)
        b_3 = b_3 ^\
              (self._get_bit(b_3, 19)) ^\
              (self._get_bit(b_3, 20) ^ (1 << 20)) ^\
              (self._get_bit(b_3, 21) ^ (1 << 21)) ^\
              (self._get_bit(b_3, 22) ^ self._get_bit(c_3, 22)) ^\
              (self._get_bit(b_3, 25) ^ (1 << 25)) ^\
              (self._get_bit(b_3, 29)) ^\
              (self._get_bit(b_3, 31))
        words[11] = self._reverse_round_operation(b_2, c_3, d_3, a_3, b_3, 19, F)
        
        # a 4,23 = 0, a 4,26 = 0, a 4,27 = b 3,27 , a 4,29 = b 3,29 ,
        # a 4,30 = 1, a 4,32 = 0
        a_4 = self._round_operation(a_3, b_3, c_3, d_3, words[12], 3, F)
        a_4 = a_4 ^\
              (self._get_bit(a_4, 22)) ^\
              (self._get_bit(a_4, 25)) ^\
              (self._get_bit(a_4, 26) ^ self._get_bit(b_3, 26)) ^\
              (self._get_bit(a_4, 28) ^ self._get_bit(b_3, 28)) ^\
              (self._get_bit(a_4, 29) ^ (1 << 29)) ^\
              (self._get_bit(a_4, 31))
        words[12] = self._reverse_round_operation(a_3, b_3, c_3, d_3, a_4, 3, F)
        
        # d 4,23 = 0, d 4,26 = 0, d 4,27 = 1, d 4,29 = 1,
        # d 4,30 = 0, d 4,32 = 1
        d_4 = self._round_operation(d_3, a_4, b_3, c_3, words[13], 7, F)
        d_4 = d_4 ^\
              (self._get_bit(d_4, 22)) ^\
              (self._get_bit(d_4, 25)) ^\
              (self._get_bit(d_4, 26) ^ (1 << 26)) ^\
              (self._get_bit(d_4, 28) ^ (1 << 28)) ^\
              (self._get_bit(d_4, 29)) ^\
              (self._get_bit(d_4, 31) ^ (1 << 31))
        words[13] = self._reverse_round_operation(d_3, a_4, b_3, c_3, d_4, 7, F)
        
        # c 4,19 = d 4,19 , c 4,23 = 1, c 4,26 = 1, c 4,27 = 0,
        # c 4,29 = 0, c 4,30 = 0
        c_4 = self._round_operation(c_3, d_4, a_4, b_3, words[14], 11, F)
        c_4 = c_4 ^\
              (self._get_bit(c_4, 18) ^ self._get_bit(d_4, 18)) ^\
              (self._get_bit(c_4, 22) ^ (1 << 22)) ^\
              (self._get_bit(c_4, 25) ^ (1 << 25)) ^\
              (self._get_bit(c_4, 26)) ^\
              (self._get_bit(c_4, 28)) ^\
              (self._get_bit(c_4, 29))
        words[14] = self._reverse_round_operation(c_3, d_4, a_4, b_3, c_4, 11, F)
        
        # b 4,19 = 0, b 4,26 = c 4,26 = 1, b 4,27 = 1, b 4,29 = 1, b 4,30 = 0
        b_4 = self._round_operation(b_3, c_4, d_4, a_4, words[15], 19, F)
        b_4 = b_4 ^\
              (self._get_bit(b_4, 18)) ^\
              (self._get_bit(b_4, 25) ^ self._get_bit(c_4, 25)) ^\
              (self._get_bit(b_4, 26) ^ (1 << 26)) ^\
              (self._get_bit(b_4, 28) ^ (1 << 28)) ^\
              (self._get_bit(b_4, 29))
        words[15] = self._reverse_round_operation(b_3, c_4, d_4, a_4, b_4, 19, F)
        
        # Now, perform multi-step modifications.
        # Still don't know how, though. Paper is totally unintelligible.  
        
    def _generate_collisions(self, words):
        # TBC
        return str(), str()
    
    def value(self, message):
        words = self.md4._get_words_from(message)
        words = self._perform_message_modifications(words)
        return self._generate_collisions(words)
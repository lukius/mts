from common.ciphers.xor import XORCipher
from common.tools import Concatenation, HammingDistance, Average
from common.freq import EnglishFrequencyScorer
from common.xor import ByteXOR


class SingleByteXORDecrypter(object):
    
    def _xor_decrypt_with(self, key, string):
        extended_key = key*len(string)
        return ByteXOR(string, extended_key).value()
    
    def _greater_than(self, number1, number2):
        return number2 is None or number1 > number2
    
    def decrypt(self, string, with_score=False):
        max_score = None
        for byte in range(256):
            byte = chr(byte)
            plaintext = self._xor_decrypt_with(byte, string)
            score = EnglishFrequencyScorer(plaintext).value()
            if self._greater_than(score, max_score):
                candidate_key = byte
                candidate_plaintext = plaintext
                max_score = score
        values = (candidate_key, candidate_plaintext)
        if with_score:
            values += (max_score,)
        return values
    
    
class RepeatingKeyXORDecrypter(object):
    
    MIN_KEY_LENGTH = 2
    MAX_KEY_LENGTH = 100
    CHUNKS = 4
    
    def _compute_average_distance_for(self, key_length, hex_string):
        chunks = self._get_byte_chunks(key_length, hex_string)
        distances = self._compute_hamming_distances_for(chunks)
        avg_distance = Average(distances).value()
        # Normalize distance before returning.
        return avg_distance/float(key_length)
    
    def _compute_hamming_distances_for(self, chunks):
        num_chunks = len(chunks)
        return [self._hamming_distance(chunks[i], chunks[j])
                for i in range(num_chunks)
                for j in range(num_chunks)
                if i != j]
    
    def _hamming_distance(self, chunk1, chunk2):
        return HammingDistance(chunk1, chunk2).value()

    def _get_byte_chunks(self, chunk_size, string):
        return [self._get_byte_chunk(i, chunk_size, string)
                for i in range(self.CHUNKS)]
    
    def _get_byte_chunk(self, i, chunk_size, string):
        return string[i*chunk_size:(i+1)*chunk_size]
    
    def _less_than(self, distance1, distance2):
        return distance2 is None or distance1 < distance2

    def _get_candidate_key_length(self, string):
        min_distance = None
        for key_length in range(self.MIN_KEY_LENGTH, self.MAX_KEY_LENGTH+1):
            distance = self._compute_average_distance_for(key_length, string)
            if self._less_than(distance, min_distance):
                candidate_length = key_length
                min_distance = distance
        return candidate_length
    
    def _build_candidate_key(self, string, key_length):
        key_bytes = [self._decipher_key_byte(i, key_length, string)
                     for i in range(key_length)]
        return Concatenation(key_bytes).value()
    
    def _build_transposed_block(self, i, block_length, string):
        length = len(string)
        block_bytes = [string[index:index+1]
                       for index in xrange(i, length, block_length)]
        return Concatenation(block_bytes).value()
    
    def _decipher_key_byte(self, i, block_length, string):
        block_i = self._build_transposed_block(i, block_length, string)
        key, _ = SingleByteXORDecrypter().decrypt(block_i)
        return key
    
    def decrypt(self, string):
        key_length = self._get_candidate_key_length(string)
        key = self._build_candidate_key(string, key_length)
        return XORCipher(key).decrypt(string)
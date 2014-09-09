import string
from collections import defaultdict


class FrequencyScorer(object):
    
    NON_LETTERS = [char for char in string.printable
                   if char not in string.letters]
    LIKELY_NON_LETTER_CHARS = [' ', '\n','.',',',';',':','"','-', '\'', '/',\
                               '!', '?'] + list(string.digits)
    
    MAX_POINTS_ON_MATCH = 8
    MIN_PENALTY = 1
    MAX_PENALTY = MAX_POINTS_ON_MATCH
    EQUALITY_TOLERANCE = 0.03
    MAX_FREQUENCY_DIFFERENCE = 0.06
    UNLIKELY_CHARS_FREQUENCY_THRESHOLD = 0.02
    
    frequencies = None
    
    def __init__(self, text):
        self.text = text
        self.normalized_text = self._normalize(text)
        self._init_tables()
        
    def _init_tables(self):
        if self.frequencies is None:
            self.__class__.frequencies = self._init_frequencies()
            self.__class__.score_table = self._init_score_table()
    
    def _init_frequencies(self):
        raise NotImplementedError
    
    def _init_score_table(self):
        score_table = dict()
        sorted_items = sorted(self.frequencies.items(),
                              key=lambda item: item[1], reverse=True)
        for (index, (char, _)) in enumerate(sorted_items, 1):
            penalty = self.MIN_PENALTY
            if index > 4:
                penalty *= 2
            if index > 12:
                penalty *= 2
            if index > 20:
                penalty *= 2
            points = self.MAX_POINTS_ON_MATCH / penalty
            score_table[char] = points 
        return score_table
    
    def _normalize(self, text):
        text = filter(lambda char: char in string.printable, text)
        text = text.lower()
        return text
    
    def _compute_frequency(self, char):
        occurrences = reduce(lambda count, letter: count + (letter==char),
                             self.normalized_text, 0)
        length = len(self.normalized_text)
        return occurrences/float(length)
        
    def _compute_frequencies(self):
        sampled_frequencies = defaultdict(lambda: 0)
        chars = list(string.lowercase) + self.NON_LETTERS
        for char in chars:
            frequency = self._compute_frequency(char)
            sampled_frequencies[char] += frequency
        return sampled_frequencies
    
    def _equals_with_tolerance(self, tolerance, number1, number2):
        return number1 - tolerance <= number2 <= number1 + tolerance
    
    def _exceeds_maximum_difference(self, sampled_frequency, frequency):
        return sampled_frequency > frequency + self.MAX_FREQUENCY_DIFFERENCE
    
    def _text_has_printable_chars_only(self):
        return len(self.normalized_text) == len(self.text)
    
    def _unlikely_chars_frequency_is_tolerable(self, sampled_frequencies):
        frequency = self._compute_unlikely_chars_frequency(sampled_frequencies)
        return frequency < self.UNLIKELY_CHARS_FREQUENCY_THRESHOLD
    
    def _compute_unlikely_chars_frequency(self, sampled_frequencies):
        unlikely_chars = [char for char in self.NON_LETTERS
                          if char not in self.LIKELY_NON_LETTER_CHARS]
        return reduce(lambda freq, char: freq + sampled_frequencies[char],
                      unlikely_chars, 0)
    
    def _compute_score_for(self, sampled_frequencies):
        score = 0
        for (char, frequency) in self.frequencies.items():
            sampled_frequency = sampled_frequencies[char]
            if self._equals_with_tolerance(self.EQUALITY_TOLERANCE, frequency,
                                           sampled_frequency):
                score += self.score_table[char]
            elif self._exceeds_maximum_difference(sampled_frequency,
                                                  frequency):
                score -= self.MAX_PENALTY
        return score
    
    def value(self):
        score = 0
        if self._text_has_printable_chars_only():
            text_frequencies = self._compute_frequencies()
            if self._unlikely_chars_frequency_is_tolerable(text_frequencies):
                score = self._compute_score_for(text_frequencies)
        return score


class EnglishFrequencyScorer(FrequencyScorer):
    
    def _init_frequencies(self):
        frequencies = dict()
        frequencies['e'] = 0.130001
        frequencies['t'] = 0.09056
        frequencies['a'] = 0.08167
        frequencies['o'] = 0.07507
        frequencies['i'] = 0.06966
        frequencies['n'] = 0.06749
        frequencies['s'] = 0.06327
        frequencies['h'] = 0.06094
        frequencies['r'] = 0.05987
        frequencies['d'] = 0.04253
        frequencies['l'] = 0.04025
        frequencies['c'] = 0.02782
        frequencies['u'] = 0.02578
        frequencies['m'] = 0.02406
        frequencies['w'] = 0.0236
        frequencies['f'] = 0.0228
        frequencies['g'] = 0.02015
        frequencies['y'] = 0.01974
        frequencies['p'] = 0.01929
        frequencies['b'] = 0.01492
        frequencies['v'] = 0.00978
        frequencies['k'] = 0.00772
        frequencies['j'] = 0.00153
        frequencies['x'] = 0.0015
        frequencies['q'] = 0.00095
        frequencies['z'] = 0.00074
        return frequencies        
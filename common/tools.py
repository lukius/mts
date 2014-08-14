class Concatenation(object):
    
    def __init__(self, objs):
        self.objs = objs
        
    def value(self):
        initial_value = type(self.objs[0])()
        return reduce(lambda result, obj: result + obj,
                      self.objs, initial_value)


class HammingDistance(object):
    
    def __init__(self, string1, string2):
        if len(string1) != len(string2):
            raise RuntimeError('strings must have equal length')        
        self.string1 = string1
        self.string2 = string2
        
    def value(self):
        from converters import ASCIIToBinary
        bin_string1 = ASCIIToBinary(self.string1).value()
        bin_string2 = ASCIIToBinary(self.string2).value()
        pairs = zip(bin_string1, bin_string2)
        differences = reduce(lambda count, (bit1,bit2): count + (bit1 != bit2),
                             pairs, 0)
        return differences
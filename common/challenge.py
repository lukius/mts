class MatasanoChallenge(object):
    
    def expected_value(self):
        raise NotImplementedError
    
    def value(self):
        raise NotImplementedError
    
    def _assert_raises(self, exception, method):
        try:
            method()
        except exception:
            return True
        else:
            return False    
    
    def validate(self):
        value = self.value()
        expected_value = self.expected_value()
        return value == expected_value
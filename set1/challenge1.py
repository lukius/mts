from common.base64 import Base64Encoder
    

if __name__ == '__main__':
    target_string = '49276d206b696c6c696e6720796f757220627261696e206c696b652'+\
                    '06120706f69736f6e6f7573206d757368726f6f6d'
    print Base64Encoder().value(target_string)
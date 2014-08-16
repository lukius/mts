from common.xor import SingleByteXORDecipher    
    
    
if __name__ == '__main__':
    target_string = '1b37373331363f78151b7f2b783431333d78397828372d363c7837'+\
                    '3e783a393b3736'
    print SingleByteXORDecipher().value(target_string)
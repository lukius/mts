from common.xor import HexXOR
    
    
if __name__ == '__main__':
    target_string1 = '1c0111001f010100061a024b53535009181c'
    target_string2 = '686974207468652062756c6c277320657965'
    print HexXOR(target_string1, target_string2).value()
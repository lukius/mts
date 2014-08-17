from common.base64 import Base64Decoder
from common.ciphers.block.cipher import AES
from common.ciphers.block.modes import ECB
from common.converters import HexToASCII

    
if __name__ == '__main__':
    target_file = 'data/7.txt'
    key = 'YELLOW SUBMARINE'
    content = open(target_file, 'r').read()
    decoded_content = Base64Decoder().value(content)
    ciphertext = HexToASCII(decoded_content).value()
    print AES(key).decrypt(ciphertext, mode=ECB())
import socket

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def customEncrypt(message, key):
    # message_ascii = [ord(c) for c in message]
    # key_ascii = [ord(c) for c in key]
    
    # encrypted_message = []
    # key_length = len(key_ascii)
    
    # message_ascii.reverse()
    
    # for i in range(len(message_ascii)):
    #     encrypted_value = message_ascii[i] * key_ascii[i % key_length]
    #     encrypted_message.append(encrypted_value)
        
    return message

def customDecrypt(message, key):
    # key_ascii = [ord(c) for c in key]
    
    # decrypted_message_ascii = []
    # key_length = len(key_ascii)
    
    # for i in range(len(encrypted_data)):
    #     decrypted_value = encrypted_data[i] // key_ascii[i % key_length]
    #     decrypted_message_ascii.append(decrypted_value)
    
    # decrypted_message_ascii.reverse()
    
    # decrypted_message = ''.join(chr(c) for c in decrypted_message_ascii)
    
    return message


def createMasterKey():
    return os.urandom(16)  
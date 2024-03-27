import socket

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad



import os

def generate_rsa_keys():
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    return private_key, public_key

def encrypt_with_key(key, message):
    cipher = PKCS1_OAEP.new(key)
    key_length_bytes = key.size_in_bytes()

    max_chunk_size = key_length_bytes - 2 * 20 - 2  

    encrypted_message = b''
    for i in range(0, len(message), max_chunk_size):
        chunk = message[i:i+max_chunk_size]
        encrypted_chunk = cipher.encrypt(chunk)
        encrypted_message += encrypted_chunk

    return encrypted_message

def decrypt_with_key(key, encrypted_message):
    cipher = PKCS1_OAEP.new(key)
    key_length_bytes = key.size_in_bytes()

    decrypted_message = b''

    for i in range(0, len(encrypted_message), key_length_bytes):
        encrypted_chunk = encrypted_message[i:i+key_length_bytes]
        decrypted_chunk = cipher.decrypt(encrypted_chunk)
        decrypted_message += decrypted_chunk

    return decrypted_message

def encrypt_with_private_key(key, message):
    # hash = SHA256.new(message)
    # signer = PKCS115_SigScheme(key)
    # signature = signer.sign(hash)
    # return signature
    return message

def decrypt_with_public_key(key, message):
    # hash = SHA256.new(message)
    # verifier = PKCS115_SigScheme(key)
    # verifier.verify(hash, signature)
    return message

def encrypt_with_session_key(session_key, data):
    cipher = AES.new(session_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    encrypted_data_with_iv = cipher.iv + ct_bytes
    return encrypted_data_with_iv

def decrypt_with_session_key(session_key, encrypted_data_with_iv):
    iv = encrypted_data_with_iv[:AES.block_size]
    ct_bytes = encrypted_data_with_iv[AES.block_size:]
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    return pt
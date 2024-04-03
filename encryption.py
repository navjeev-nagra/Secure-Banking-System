import socket
import logging
from cryptography.hazmat.primitives.serialization import load_pem_public_key
#from Crypto.Cipher import PKCS1_OAEP
#from Crypto.PublicKey import RSA
#from Crypto.Cipher import AES
#from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import os

def customEncrypt(message, encryption_key):
    message_bytes = message.encode()
    encrypted_message = bytearray()
    key_integer = int.from_bytes(encryption_key, byteorder='big') % 256
    for byte in message_bytes:
        encrypted_byte = byte ^ key_integer
        encrypted_message.append(encrypted_byte)

    return bytes(encrypted_message)

def customDecrypt(encrypted_message, encryption_key):
    decrypted_message_bytes = bytearray()
    key_integer = int.from_bytes(encryption_key, byteorder='big') % 256
    for byte in encrypted_message:
        decrypted_byte = byte ^ key_integer
        decrypted_message_bytes.append(decrypted_byte)
    decrypted_message = decrypted_message_bytes.decode()

    return decrypted_message

def simpleEncrypt(message, key):
    encrypted = bytearray()
    key_index = 0
    for char in message:
        encrypted_char = char ^ key[key_index]
        encrypted.append(encrypted_char)
        key_index = (key_index + 1) % len(key)
    return message

def simpleDecrypt(message, key):
    decrypted = bytearray()
    key_index = 0
    for char in message:
        decrypted_char = char ^ key[key_index]
        decrypted.append(decrypted_char)
        key_index = (key_index + 1) % len(key)
    return message

def generate_mac(data, mac_key):
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return base64.b64encode(h.finalize())

def verify_mac(data, mac_key, received_mac):
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    try:
        h.verify(base64.b64decode(received_mac))
        return True
    except Exception as e:
        return False

def derive_keys(master_key):
    backend = default_backend()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Generates 32 bytes: 16 for encryption, 16 for MAC
        salt=None,
        info=b'handshake data',
        backend=backend
    )

    derived_key = hkdf.derive(master_key)

    # Split the derived key into two parts: one for encryption, one for MAC
    encryption_key = derived_key[:16]
    mac_key = derived_key[16:]

    return encryption_key, mac_key

def createMasterKey():
    return os.urandom(16)

# Basic Caesar Cipher implementation
def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            result += chr((ord(char) - offset + shift) % 26 + offset)
        else:
            result += char
    return result
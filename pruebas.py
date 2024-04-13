from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from os import urandom
from base64 import urlsafe_b64encode, urlsafe_b64decode
from Crypto.PublicKey import RSA
import binascii

def encrypt_message(message, public_key):
    # Crear un objeto de cifrado RSA con PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return binascii.hexlify(encrypted_message).decode()

# Uso del método de cifrado
public_key=""
encrypted_msg = encrypt_message("Hola mundo!", "HOLA")
print("Mensaje cifrado:", encrypted_msg)
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_file: str, output_file: str, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, "rb") as f:
        plaintext = f.read()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # store: salt (16) + iv (16) + ciphertext
    with open(output_file, "wb") as f:
        f.write(salt + iv + ciphertext)

def decrypt_file(input_file: str, output_file: str, password: str):
    with open(input_file, "rb") as f:
        data = f.read()

    if len(data) < 32:
        raise ValueError("Invalid encrypted file format")

    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(output_file, "wb") as f:
        f.write(plaintext)

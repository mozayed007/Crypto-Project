import pgpy
import os
import time
import base64
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from pgpy import PGPKey
from pgpy.constants import SymmetricKeyAlgorithm, CompressionAlgorithm, HashAlgorithm, KeyFlags ,PubKeyAlgorithm 

class SymmetricPGPKey:
    def __init__(self, key):
        self._key = key

    def encrypt(self, message, **kwargs):
        return message.encrypt(self._key, **kwargs)

    def decrypt(self, encrypted_message):
        return encrypted_message.decrypt(self._key)



def encrypt(data, password):
    """
    Encrypt the input data using OpenPGP CFB mode.
    
    Args:
        data (bytes): The plaintext data to be encrypted.
        password (str): The password used for key derivation.
    
    Returns:
        str: The encrypted data.
    """
    # Generate a symmetric key from the password and a random salt
    salt = generate_salt()
    key_material = PBKDF2(password, salt, dkLen=32)
    key = SymmetricPGPKey(key_material)

    # Create a new PGP message from the input data
    message = pgpy.PGPMessage.new(data)

    # Encrypt the message using the symmetric key
    encrypted_message = key.encrypt(message,
                                    cipher=SymmetricKeyAlgorithm.AES256,
                                    compression=CompressionAlgorithm.ZLIB,
                                    hashfunc=HashAlgorithm.SHA256)

    return str(encrypted_message),salt


def generate_salt(size=16):
    """
    Generate a random salt.
    
    Args:
        size (int, optional): The size of the generated salt. Defaults to 16.
    
    Returns:
        bytes: A random salt.
    """
    return get_random_bytes(size)


def measure_time(func, *args, **kwargs):
    """
    Measure the execution time of a function.
    
    Args:
        func (callable): The function to measure the time of.
        *args: Positional arguments to pass to the function.
        **kwargs: Keyword arguments to pass to the function.
        
    Returns:
        tuple: A tuple containing the result of the function and the time taken in seconds.
    """
    start_time = time.perf_counter()
    result = func(*args, **kwargs)
    end_time = time.perf_counter()
    return result, end_time - start_time


if __name__ == "__main__":
    file_sizes = ['1KB', '5KB', '10KB', '100KB']
    password = "my_password"
    os.makedirs("OpenPGP", exist_ok=True)

    # OpenPGP: Encrypt and measure performance for different file sizes
    for size in file_sizes:
        with open(f"{size}_file.txt", "rb") as f:
            data = f.read()

        result, encryption_time = measure_time(encrypt, data, password)
        encrypted_data, salt = result
        with open(f"OpenPGP/salt_{size}.bin", "wb") as f:
            f.write(salt)

        print(f"Encryption time for OpenPGP-CFB ({size}): {encryption_time:.4f} seconds")

        with open(f"OpenPGP/encrypted_{size}_OpenPGP_CFB_file.txt", "w") as f:
            f.write(base64.b64encode(encrypted_data.encode('utf-8')).decode('utf-8'))

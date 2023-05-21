#encryption module#
import os
import time
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
     

def pad(data, block_size=16):
    """
    Add PKCS padding to the input data.
    
    Args:
        data (bytes): The data to be padded.
        block_size (int, optional): The block size used for padding. Defaults to 16.
    
    Returns:
        bytes: The padded data.
    """
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length

def encrypt(data, password):
    """
    Encrypt the input data using AES with PGP-CFB mode.
    
    Args:
        data (bytes): The plaintext data to be encrypted.
        password (str): The password used for key derivation.
    
    Returns:
        bytes: The encrypted data (salt + IV + encrypted_data).
    """
    salt = get_random_bytes(16)
    key, iv = generate_key_iv(password, salt)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted_data = cipher.encrypt(pad(data))
    return salt + iv + encrypted_data

def generate_key_iv(password, salt, key_size=32, iv_size=16):
    """
    Generate a key and IV from the given password and salt.
    
    Args:
        password (str): The password used for key derivation.
        salt (bytes): The salt used for key derivation.
        key_size (int, optional): The size of the derived key. Defaults to 32.
        iv_size (int, optional): The size of the initialization vector. Defaults to 16.
    
    Returns:
        tuple: A tuple containing the derived key and IV.
    """
    key = PBKDF2(password, salt, dkLen=key_size)
    iv = get_random_bytes(iv_size)
    return key, iv

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
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    return result, end_time - start_time


if __name__ == "__main__":
    file_sizes = [1, 5, 10, 100]
    password = "my_password"

    # Encrypt and measure performance for different file sizes
    for size in file_sizes:
        file_name = f"message_{size}KB.txt"
        with open(file_name, "rb") as f:
            plaintext = f.read()

        encrypted_data, encryption_time = measure_time(encrypt, plaintext, password)
        print(f"Encryption time for PGP-CFB ({size}KB): {encryption_time:.4f} seconds")

        with open(f"encrypted_{size}KB.txt", "wb") as f:
            f.write(encrypted_data)

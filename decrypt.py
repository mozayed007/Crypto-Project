#decrypt module#
import os
import time
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

def unpad(data):
    """
    Remove PKCS padding from the input data.
    
    Args:
        data (bytes): The data to be unpadded.
    
    Returns:
        bytes: The unpadded data.
    """
    padding_length = data[-1]
    return data[:-padding_length]

def decrypt(data, password):
    """
    Decrypt the input data using AES with PGP-CFB mode.
    
    Args:
        data (bytes): The encrypted data (salt + IV + encrypted_data).
        password (str): The password used for key derivation.
    
    Returns:
        bytes: The decrypted data.
    """
    salt = data[:16]
    iv = data[16:32]
    encrypted_data = data[32:]
    key, _ = generate_key_iv(password, salt)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data)

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

    # Decrypt and measure performance for different file sizes
    for size in file_sizes:
        with open(f"encrypted_{size}KB.txt", "rb") as f:
            encrypted_data = f.read()

        decrypted_data, decryption_time = measure_time(decrypt, encrypted_data, password)
        print(f"Decryption time for PGP-CFB ({size}KB): {decryption_time:.4f} seconds")

        with open(f"decrypted_{size}KB.txt", "wb") as f:
            f.write(decrypted_data)

        # Verify successful decryption by comparing the original and decrypted data
        with open(f"message_{size}KB.txt", "rb") as f:
            original_data = f.read()

        if original_data == decrypted_data:
            print(f"Successful decryption for PGP-CFB ({size}KB)")
        else:
            print(f"Decryption failed for PGP-CFB ({size}KB)")

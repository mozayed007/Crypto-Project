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
    if padding_length > len(data) or data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("Invalid padding")
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
    key, _ = generate_key_iv(password, salt, iv=iv)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data)


def generate_key_iv(password, salt, key_size=32, iv_size=16, iv=None):
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
    if iv is None:
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
    start_time = time.perf_counter()
    result = func(*args, **kwargs)
    end_time = time.perf_counter()
    return result, end_time - start_time

if __name__ == "__main__":
    file_sizes = ['1KB', '5KB', '10KB', '100KB']
    password = "my_password"
    os.makedirs("Standard_AES", exist_ok=True)
    # Standard_AES: Decrypt and measure performance for different file sizes
    for size in file_sizes:
        with open(f"Standard_AES/encrypted_{size}_standard_AES_CFB_file.txt", "rb") as f:
            encrypted_data = f.read()

        decrypted_data, decryption_time = measure_time(decrypt, encrypted_data, password)
        print(f"Decryption time for Standard AES-CFB ({size}): {decryption_time:.4f} seconds")

        with open(f"Standard_AES/decrypted_{size}_standard_AES_CFB_file.txt", "wb") as f:
            f.write(decrypted_data)

        # Verify successful decryption by comparing the original and decrypted data
        with open(f"{size}_file.txt", "rb") as f:
            original_data = f.read()

        if original_data == decrypted_data:
            print(f"Successful decryption for Standard AES-CFB ({size})")
        else:
            print(f"Decryption failed for Standard AES-CFB ({size})")

import pgpy
import os
import time
from Crypto.Protocol.KDF import PBKDF2
from pgpy import PGPKey
from pgpy.constants import PubKeyAlgorithm
from encrypt_OpenPGP_CFB import SymmetricPGPKey
import base64


def decrypt(encrypted_data, password, salt):
    """
    Decrypt the input data using OpenPGP CFB mode.
    
    Args:
        encrypted_data (str): The encrypted data to be decrypted.
        password (str): The password used for key derivation.
    
    Returns:
        bytes: The decrypted data.
    """
    encrypted_message = pgpy.PGPMessage.from_blob(encrypted_data)
    if not encrypted_message.is_encrypted:
        raise ValueError("The input data is not an encrypted message")

    # Generate a symmetric key from the password
    key_material = PBKDF2(password, salt, dkLen=32)  # Replace 'b'salt'' with the proper salt value used during encryption
    key = SymmetricPGPKey(key_material)

    decrypted_message = key.decrypt(encrypted_message)
    return decrypted_message._message.contents


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

    # OpenPGP: Decrypt and measure performance for different file sizes
    for size in file_sizes:
        with open(f"OpenPGP/encrypted_{size}_OpenPGP_CFB_file.txt", "r") as f:
            encrypted_data_base64 = f.read()

        with open(f"OpenPGP/salt_{size}.bin", "rb") as f:
            salt = f.read()

        decrypted_data, decryption_time = measure_time(decrypt, base64.b64decode(encrypted_data_base64), password, salt)
        print(f"Decryption time for OpenPGP-CFB ({size}): {decryption_time:.4f} seconds")

        with open(f"OpenPGP/decrypted_{size}_OpenPGP_CFB_file.txt", "wb") as f:
            f.write(decrypted_data)

        # Verify successful decryption by comparing the original and decrypted data
        with open(f"{size}_file.txt", "rb") as f:
            original_data = f.read()

        if original_data == decrypted_data:
            print(f"Successful decryption for OpenPGP-CFB ({size})")
        else:
            print(f"Decryption failed for OpenPGP-CFB ({size})")
#(main.py module)
import os
import time
from Crypto.Random import get_random_bytes
from encrypt_standard_AES_CFB import encrypt as encrypt_standard_aes
from decrypt_standard_AES_CFB import decrypt as decrypt_standard_aes
from PGP_CFB import PGP_CFB
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Function to read the file content
def read_file(file_path):
    """
    Reads a file at a given file path and returns its contents as bytes.

    :param file_path: A string representing the path to the file to be read.
    :return: A bytes object representing the contents of the file.
    """
    with open(file_path, "rb") as f:
        return f.read()

# Function to write the file content
def write_file(file_path, data):
    """
    Writes data to a file at a specified file path. 

    :param file_path: A string representing the path to the file.
    :type file_path: str
    :param data: The data to be written to the file.
    :type data: bytes
    """
    with open(file_path, "wb") as f:
        f.write(data)

# Function to create a folder if it doesn't exist
def create_folder(folder_name):
    """
    Creates a folder at a specified path if it doesn't exist.

    :param folder_name: A string representing the path to the folder to be created.
    :type folder_name: str
    """
    
    if not os.path.exists(folder_name):
        os.makedirs(folder_name, exist_ok=True)
# Functions for RSA encryption and decryption
def encrypt_RSA(data, key):
    """
    Encrypts data using RSA encryption with a given public key.

    Args:
        data (bytes): The data to be encrypted.
        key (RSA.RsaKey): The public key used for encryption.

    Returns:
        bytes: The encrypted data.
    """
    cipher = PKCS1_OAEP.new(key)
    max_length = (key.size_in_bytes() - 42)  # Maximum length of plaintext for RSA key
    encrypted_data = b''

    # Split data into chunks and encrypt each chunk
    for i in range(0, len(data), max_length):
        chunk = data[i:i + max_length]
        encrypted_data += cipher.encrypt(chunk)

    return encrypted_data

def decrypt_RSA(encrypted_data, key):
    """
    Decrypts RSA encrypted data using the given RSA key.

    Args:
        encrypted_data (bytes): The data to decrypt.
        key (RSA key): The RSA key to use for decryption.

    Returns:
        bytes: The decrypted data.
    """
    cipher = PKCS1_OAEP.new(key)
    decrypted_data = b''
    chunk_size = key.size_in_bytes()

    # Decrypt each chunk
    for i in range(0, len(encrypted_data), chunk_size):
        chunk = encrypted_data[i:i + chunk_size]
        decrypted_data += cipher.decrypt(chunk)

    return decrypted_data


# Main function
def main():
    """
    A function that performs performance comparisons of different encryption algorithms and writes the encrypted and decrypted files to their corresponding folders. 
    
    Parameters:
    None

    Returns:
    None
    """
    # Define the file sizes and key
    file_sizes = [1, 5, 10, 100]
    key = get_random_bytes(32) # Use 32 bytes (256 bits) for the AES key

    # Create output folders if they don't exist
    create_folder("Standard_AES")
    create_folder("OpenPGP")
    create_folder("PGP-CFB")

    # Encrypt and decrypt the test files using the respective algorithms and output them to the respective folders
    for file_size in file_sizes:
        file_path = f"{file_size}KB_file.txt"
        data = read_file(file_path)

        # Standard AES CFB
        start_time = time.time()
        encrypted_data = encrypt_standard_aes(data, key)
        end_time = time.time()
        standard_aes_encryption_time = end_time - start_time
        start_time = time.time()
        decrypted_data = decrypt_standard_aes(encrypted_data, key)
        end_time = time.time()
        standard_aes_decryption_time = end_time - start_time
        standard_aes_time = standard_aes_encryption_time + standard_aes_decryption_time
        # PGP-CFB
        start_time = time.time()
        pgp_cfb = PGP_CFB(key)
        encrypted_data = pgp_cfb.encrypt(data)
        end_time = time.time()
        pgp_encryption_time = end_time - start_time
        start_time = time.time()
        decrypted_data = pgp_cfb.decrypt(encrypted_data)
        end_time = time.time()
        pgp_decryption_time = end_time - start_time
        pgp_cfb_time = pgp_encryption_time + pgp_decryption_time
        
        if file_size in [1,5]:
            # RSA encryption and decryption
            rsa_key_size = 2048  # Use 2048 bits for RSA key size
            rsa_key = RSA.generate(rsa_key_size)
            public_key = rsa_key.publickey()
            private_key = rsa_key

            start_time = time.time()
            rsa_encrypt_data = encrypt_RSA(data, public_key)
            end_time = time.time()
            rsa_encryption_time = end_time - start_time

            start_time = time.time()
            rsa_decrypt_data = decrypt_RSA(rsa_encrypt_data, private_key)
            end_time = time.time()
            rsa_decryption_time = end_time - start_time
            rsa_time = rsa_encryption_time + rsa_decryption_time
        # Print performance comparison

        print(f"Performance Comparison:")
        print("==================================")
        print(f"File size: {file_size} KB")
        print("\n")
        print(f"Standard AES CFB Encryption: {standard_aes_encryption_time:.4f} seconds")
        print(f"Standard AES Decryption: {standard_aes_decryption_time:.4f} seconds")        
        print(f"Standard AES CFB: {standard_aes_time:.4f} seconds")
        print("\n")
        print(f"PGP-CFB CFB Encryption: {pgp_encryption_time:.4f} seconds")
        print(f"PGP-CFB Decryption: {pgp_decryption_time:.4f} seconds")        
        print(f"PGP-CFB: {pgp_cfb_time:.4f} seconds")
        print("\n")
        if file_size in [1,5]:
                print(f"RSA Encryption: {rsa_encryption_time:.4f} seconds")
                print(f"RSA Decryption: {rsa_decryption_time:.4f} seconds")
                print(f"RSA: {rsa_time:.4f} seconds")
        print("\n")
        write_file(f"Standard_AES/{file_size}KB_encrypted.txt", encrypted_data)
        write_file(f"Standard_AES/{file_size}KB_decrypted.txt", decrypted_data)
        write_file(f"PGP-CFB/{file_size}KB_encrypted.txt", encrypted_data)
        write_file(f"PGP-CFB/{file_size}KB_decrypted.txt", decrypted_data)

# Call the main function
if __name__ == "__main__":
    main()

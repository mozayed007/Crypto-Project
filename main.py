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
    with open(file_path, "rb") as f:
        return f.read()

# Function to write the file content
def write_file(file_path, data):
    with open(file_path, "wb") as f:
        f.write(data)

# Function to create a folder if it doesn't exist
def create_folder(folder_name):
    if not os.path.exists(folder_name):
        os.makedirs(folder_name, exist_ok=True)

# Functions for RSA encryption and decryption
# Functions for RSA encryption and decryption
def encrypt_RSA(data, key):
    cipher = PKCS1_OAEP.new(key)
    max_length = (key.size_in_bytes() - 42)  # Maximum length of plaintext for RSA key
    encrypted_data = b''

    # Split data into chunks and encrypt each chunk
    for i in range(0, len(data), max_length):
        chunk = data[i:i + max_length]
        encrypted_data += cipher.encrypt(chunk)

    return encrypted_data

def decrypt_RSA(encrypted_data, key):
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
        decrypted_data = decrypt_standard_aes(encrypted_data, key)
        end_time = time.time()
        standard_aes_time = end_time - start_time

        # # OpenPGP CFB
        # start_time = time.time()
        # encrypted_data = encrypt_openpgp(data, key)
        # decrypted_data = decrypt_openpgp(encrypted_data, key)
        # end_time = time.time()
        # openpgp_time = end_time - start_time

        # PGP-CFB
        start_time = time.time()
        pgp_cfb = PGP_CFB(key)
        encrypted_data = pgp_cfb.encrypt(data)
        decrypted_data = pgp_cfb.decrypt(encrypted_data)
        end_time = time.time()
        pgp_cfb_time = end_time - start_time
        
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
        print(f"File size: {file_size} KB")
        print(f"Standard AES CFB: {standard_aes_time:.4f} seconds")
        print(f"PGP-CFB: {pgp_cfb_time:.4f} seconds")
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

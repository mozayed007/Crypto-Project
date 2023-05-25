import os
from encrypt_standard_AES_CFB import encrypt as encrypt_standard_aes
from decrypt_standard_AES_CFB import decrypt as decrypt_standard_aes
from encrypt_OpenPGP_CFB import encrypt as encrypt_openpgp
from decrypt_OpenPGP_CFB import decrypt as decrypt_openpgp
from PGP_CFB import PGP_CFB

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

# Main function
def main():
    # Define the file sizes and key
    file_sizes = [1, 5, 10, 100]
    key = os.urandom(16)  # 16 bytes (128 bits) key for AES-128

    # Create output folders if they don't exist
    create_folder("Standard_AES")
    create_folder("OpenPGP")
    create_folder("PGP-CFB")

    # Encrypt and decrypt the test files using the respective algorithms and output them to the respective folders
    for file_size in file_sizes:
        file_path = f"{file_size}KB_file.txt"
        data = read_file(file_path)

        # Standard AES CFB
        encrypted_data = encrypt_standard_aes(data, key)
        decrypted_data = decrypt_standard_aes(encrypted_data, key)
        write_file(f"Standard_AES/{file_size}KB_encrypted.txt", encrypted_data)
        write_file(f"Standard_AES/{file_size}KB_decrypted.txt", decrypted_data)

        # OpenPGP CFB
        encrypted_data = encrypt_openpgp(data, key)
        decrypted_data = decrypt_openpgp(encrypted_data, key)
        write_file(f"OpenPGP/{file_size}KB_encrypted.txt", encrypted_data)
        write_file(f"OpenPGP/{file_size}KB_decrypted.txt", decrypted_data)

        # PGP-CFB
        pgp_cfb = PGP_CFB(key)
        encrypted_data = pgp_cfb.encrypt(data)
        decrypted_data = pgp_cfb.decrypt(encrypted_data)
        write_file(f"PGP-CFB/{file_size}KB_encrypted.txt", encrypted_data)
        write_file(f"PGP-CFB/{file_size}KB_decrypted.txt", decrypted_data)

# Call the main function
if __name__ == "__main__":
    main()

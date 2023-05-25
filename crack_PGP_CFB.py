import os
from hashlib import sha256
from Crypto.Cipher import AES
from PGP_CFB_old import PGP_CFB

# Function to read the plaintext input
def read_plaintext():
    return input("Enter the plaintext to be encrypted: ")

# Function to write the file content
def write_file(file_path, data):
    with open(file_path, "wb") as f:
        f.write(data)

# Attempt to crack the PGP-CFB encryption using a known portion of the plaintext
def crack_pgp_cfb(encrypted_data, known_plaintext, key, block_size=32):
    iv = encrypted_data[:block_size]
    encrypted_data = encrypted_data[block_size:]
    aes = AES.new(key, AES.MODE_ECB)

    # XOR the known plaintext with the corresponding ciphertext block to recover a portion of the encryption of the IV
    recovered_iv_portion = bytes(x ^ y for x, y in zip(known_plaintext, encrypted_data[:len(known_plaintext)]))

    # Bruteforce the remaining portion of the encryption of the IV
    for i in range(256 ** (block_size - len(known_plaintext))):
        iv_guess = recovered_iv_portion + i.to_bytes(block_size - len(known_plaintext), 'little')
        pgp_cfb = PGP_CFB(key, block_size)
        decrypted_data = pgp_cfb.decrypt(iv + encrypted_data)

        # Check if the decrypted data starts with the known plaintext
        if decrypted_data.startswith(known_plaintext):
            print("Cracked PGP-CFB encryption!")
            return decrypted_data

    print("Failed to crack PGP-CFB encryption.")
    return None

def main():
    key = os.urandom(32)
    pgp_cfb = PGP_CFB(key)

    # Encrypt a sample plaintext and write the encrypted data to a file
    plaintext = read_plaintext()
    encrypted_data = pgp_cfb.encrypt(plaintext)
    write_file("encrypted_sample.txt", encrypted_data)

    # Try to crack the PGP-CFB encryption using a known portion of the plaintext
    known_plaintext = b"Known portion of plaintext"
    cracked_data = crack_pgp_cfb(encrypted_data, known_plaintext, key)

    if cracked_data:
        write_file("cracked_sample.txt", cracked_data)

if __name__ == "__main__":
    main()

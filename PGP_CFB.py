#(PGP_CFB module)
import os
from hashlib import sha256
from Crypto.Cipher import AES

class PGP_CFB:
    def __init__(self, key, block_size=32):
        self.key = key
        self.block_size = block_size

    # PKCS padding method
    def pad(self, data):
        pad_len = self.block_size - len(data) % self.block_size
        return data + (pad_len * chr(pad_len)).encode('utf-8')

    # PKCS unpadding method
    def unpad(self, data):
        pad_len = data[-1]
        return data[:-pad_len]

    # XOR operation on two byte arrays
    def xor_bytes(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    # Encryption method implementing PGP-CFB mode using AES in ECB mode
    def encrypt(self, data):
        padded_data = self.pad(data)
        iv = os.urandom(self.block_size)
        aes = AES.new(self.key, AES.MODE_ECB)
        encrypted_data = bytearray()
        prev_cipher_block = iv

        # Iterate through padded data blocks and apply XOR operation
        for i in range(0, len(padded_data), self.block_size):
            plaintext_block = padded_data[i:i+self.block_size]
            cipher_block = self.xor_bytes(plaintext_block, aes.encrypt(prev_cipher_block))
            encrypted_data.extend(cipher_block)
            prev_cipher_block = cipher_block

        return iv + encrypted_data

    # Decryption method implementing PGP-CFB mode using AES in ECB mode
    def decrypt(self, data):
        iv = data[:self.block_size]
        encrypted_data = data[self.block_size:]
        aes = AES.new(self.key, AES.MODE_ECB)
        decrypted_data = bytearray()
        prev_cipher_block = iv

        # Iterate through encrypted data blocks and apply XOR operation
        for i in range(0, len(encrypted_data), self.block_size):
            cipher_block = encrypted_data[i:i+self.block_size]
            plaintext_block = self.xor_bytes(cipher_block, aes.encrypt(prev_cipher_block))
            decrypted_data.extend(plaintext_block)
            prev_cipher_block = cipher_block

        return self.unpad(decrypted_data)

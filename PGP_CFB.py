import os
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

class PGP_CFB:
    def __init__(self, password, block_size=16, salt_size=16, iterations=10000):
        """
        Initializes a new instance of the class with the given password, block size, salt size, and number of iterations.

        :param password: The password to be used for key derivation.
        :type password: str
        :param block_size: The block size to use for encryption. Defaults to 16.
        :type block_size: int
        :param salt_size: The size of the salt to be generated. Defaults to 16.
        :type salt_size: int
        :param iterations: The number of iterations to use for key derivation. Defaults to 10000.
        :type iterations: int
        """
        self.block_size = block_size
        self.salt = get_random_bytes(salt_size)
        self.key = PBKDF2(password, self.salt, dkLen=32, count=iterations)

    def pad(self, data):
        """
        Pad the input data with the required number of bytes so that it can be evenly
        divided into blocks of the specified block size.
        :param data: The input data to pad.
        :type data: bytes
        :return: The padded data.
        :rtype: bytes
        """
        pad_len = self.block_size - len(data) % self.block_size
        return data + (pad_len * chr(pad_len)).encode('utf-8')

    def unpad(self, data):
        """
        Removes padding from the given data and returns the original unpadded data.

        :param data: A byte string that has been padded.
        :type data: bytes
        :return: The unpadded byte string.
        :rtype: bytes
        """
        pad_len = data[-1]
        return data[:-pad_len]

    def xor_bytes(self, a, b):
        """
        Performs a bitwise XOR operation between two byte arrays, element-wise.

        :param a: A byte array.
        :type a: bytes
        :param b: A byte array.
        :type b: bytes
        :return: A new byte array containing the result of the XOR operation.
        :rtype: bytes
        """
        return bytes(x ^ y for x, y in zip(a, b))

    def encrypt(self, data):
        """
        Encrypts the given data using AES in CBC mode.

        :param data: The data to be encrypted.
        :type data: bytes
        :return: The encrypted data with salt and iv prepended.
        :rtype: bytearray
        """
        padded_data = self.pad(data)
        iv = os.urandom(self.block_size)
        aes = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_data = bytearray()
        prev_cipher_block = iv

        for i in range(0, len(padded_data), self.block_size):
            plaintext_block = padded_data[i:i+self.block_size]
            cipher_block = self.xor_bytes(plaintext_block, aes.encrypt(prev_cipher_block))
            encrypted_data.extend(cipher_block)
            prev_cipher_block = cipher_block

        return self.salt + iv + encrypted_data

    def decrypt(self, data):
        """
        Decrypts the given data using AES with CBC mode and returns the decrypted data.
        
        Args:
            data (bytearray): The data to be decrypted.
        
        Returns:
            bytearray: The decrypted data.
        """
        salt = data[:self.block_size]
        iv = data[self.block_size:2*self.block_size]
        encrypted_data = data[2*self.block_size:]
        aes = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = bytearray()
        prev_cipher_block = iv

        for i in range(0, len(encrypted_data), self.block_size):
            cipher_block = encrypted_data[i:i+self.block_size]
            plaintext_block = self.xor_bytes(cipher_block, aes.encrypt(prev_cipher_block))
            decrypted_data.extend(plaintext_block)
            prev_cipher_block = cipher_block

        return self.unpad(decrypted_data)

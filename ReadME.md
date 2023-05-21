# PGP-CFB and Standard AES-CFB Encryption and Decryption

This project implements PGP-CFB and Standard AES-CFB modes for encryption and decryption using AES as the block cipher and PKCS for padding. The code also includes performance evaluation for different file sizes.

The test msg files are predefined in the format of  ` {sizeKB}_file.txt` 

## Requirements

- Python 3.6 or higher
- PyCryptodome
- PGPy

## Installation

1. Install Python 3.6 or higher if not already installed.

2. Install PyCryptodome and PGPy using pip:

   ` pip install pycryptodome pgpy` 


## Usage

### PGP-CFB

1. Run the `encrypt_OpenPGP_CFB.py` script to encrypt files of different sizes and measure the encryption time:

`  python encrypt_OpenPGP_CFB.py`  


2. Run the `decrypt_OpenPGP_CFB.py` script to decrypt the encrypted files and measure the decryption time:

`  python decrypt_OpenPGP_CFB.py` 


### Standard AES-CFB

1. Run the `encrypt_standard_AES_CFB.py` script to encrypt files of different sizes and measure the encryption time:

`  python encrypt_standard_AES_CFB.py` 


2. Run the `decrypt_standard_AES_CFB.py` script to decrypt the encrypted files and measure the decryption time:

` python decrypt_standard_AES_CFB.py` 


## Resources

- [RFC4880: OpenPGP Message Format](https://tools.ietf.org/html/rfc4880)
- [PyCryptodome Documentation](https://pycryptodome.readthedocs.io/en/latest/)
- [PGPy Documentation](https://pgpy.readthedocs.io/en/latest/)
- [Serge Mister & Robert Zuccherato's Paper on PGP-CFB Attack](https://eprint.iacr.org/2005/033.pdf)
- [StackOverflow: Encrypt in python and decrypt in Java with AES-CFB](https://stackoverflow.com/questions/40004858/encrypt-in-python-and-decrypt-in-java-with-aes-cfb)
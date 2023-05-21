# PGP-CFB Encryption and Decryption

This project implements PGP-CFB mode for encryption and decryption using AES as the block cipher and PKCS for padding. The code also includes performance evaluation for different file sizes and demonstrates an attack on the PGP-CFB mode.

## Requirements

- Python 3.6 or higher
- PyCryptodome

## Installation

1. Install Python 3.6 or higher if not already installed.
2. Install PyCryptodome using pip:

``` pip install pycryptodome ```

## Usage

1. Run the `encrypt.py` script to encrypt files of different sizes and measure the encryption time:

``` python encrypt.py ```

2. Run the `decrypt.py` script to decrypt the encrypted files and measure the decryption time:

``` python decrypt.py ```

3. Run the `crack.py` script to demonstrate the attack on PGP-CFB mode:

``` python crack.py ```

## Resources

- [RFC4880: OpenPGP Message Format](https://tools.ietf.org/html/rfc4880)
- [PyCryptodome Documentation](https://pycryptodome.readthedocs.io/en/latest/)
- [Serge Mister & Robert Zuccherato's Paper on PGP-CFB Attack](https://eprint.iacr.org/2005/033.pdf)
- [StackOverflow: Encrypt in python and decrypt in Java with AES-CFB](https://stackoverflow.com/questions/40004858/encrypt-in-python-and-decrypt-in-java-with-aes-cfb)
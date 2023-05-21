#crack module#
from encrypt import pad, encrypt, generate_key_iv
from decrypt import unpad, decrypt, measure_time

def attacker_decrypt(data, password):
    """
    Simulate the attacker's decryption attempt. Returns None if the decryption
    fails due to invalid padding.
    
    Args:
        data (bytes): The manipulated ciphertext (salt + IV + encrypted_data).
        password (str): The password used for key derivation.
    
    Returns:
        bytes or None: The decrypted data, or None if decryption fails due to invalid padding.
    """
    try:
        decrypted_data = decrypt(data, password)
        unpad(decrypted_data)
        return decrypted_data
    except ValueError:
        return None

def demonstrate_attack(plaintext, password):
    """
    Demonstrates the attack on the PGP-CFB implementation.
    
    Args:
        plaintext (bytes): The plaintext data to be encrypted and attacked.
        password (str): The password used for key derivation.
    
    Returns:
        bool: True if the attack is successful, False otherwise.
    """
    encrypted_data = encrypt(plaintext, password)
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    original_ciphertext = encrypted_data[32:]

    # Choose a target block and replace it with a chosen block (e.g., all zeros)
    chosen_block = b'\x00' * 16
    manipulated_ciphertext = original_ciphertext[:16] + chosen_block + original_ciphertext[32:]

    # Attempt to decrypt the manipulated ciphertext
    manipulated_data = attacker_decrypt(salt + iv + manipulated_ciphertext, password)

    if manipulated_data is not None:
        # Recover the original plaintext block by XORing the manipulated block with the decrypted block
        recovered_block = bytes(a ^ b for a, b in zip(chosen_block, manipulated_data[16:32]))

        # Check if the attack is successful
        if recovered_block == plaintext[16:32]:
            return True

    return False

if __name__ == "__main__":
    plaintext = b"This is a test message. We will demonstrate the attack on PGP-CFB mode."
    password = "my_password"

    success = demonstrate_attack(plaintext, password)
    if success:
        print("Attack on PGP-CFB mode was successful!")
    else:
        print("Attack on PGP-CFB mode failed.")

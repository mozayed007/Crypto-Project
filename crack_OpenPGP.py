import os
import base64
from encrypt_OpenPGP_CFB import encrypt, generate_salt
from decrypt_OpenPGP_CFB import decrypt, measure_time


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(map(int, a), map(int, b)))

def oracle_decrypt_function(modified_packet, password, salt, convert_to_bytes=False):
    try:
        decrypted_data = decrypt(modified_packet, password, salt)
        if convert_to_bytes:
            return decrypted_data.encode('utf-8')  # Convert the decrypted data from str to bytes
        else:
            return decrypted_data  # No conversion needed
    except ValueError:
        return None

def mister_zuccherato_attack(encrypted_data, oracle_decrypt_function):
    """
    Implements the adaptive chosen-ciphertext attack on OpenPGP-CFB mode as described
    by Mister and Zuccherato in their 2005 paper.

    Args:
        encrypted_data (bytes): The encrypted data to be attacked.
        oracle_decrypt_function (callable): A function that takes encrypted data and
                                            returns decrypted data or an error.

    Returns:
        bytes: The decrypted data if the attack was successful, otherwise None.
    """
    # Step 1: Start with an encrypted packet (encrypted_data)
    modified_packet = bytearray(encrypted_data)

    # Step 2: Modify the encrypted packet to generate a modified packet
    # Flip the bits of the second byte of the packet
    modified_packet[1] ^= 0xFF

    # Step 3: Use the oracle_decrypt_function to check if the modified packet has a valid ad-hoc integrity check
    decryption_result = oracle_decrypt_function(modified_packet)

    # Step 4: Based on the oracle's response, continue modifying the packet until the integrity check is valid
    while decryption_result is None:
        # Modify the second byte of the packet by flipping one bit at a time
        for i in range(8):
            modified_packet[1] ^= (1 << i)
            decryption_result = oracle_decrypt_function(modified_packet)
            if decryption_result is not None:
                break

    # Step 5: Recover the decrypted plaintext
    # Calculate the difference between the first two bytes of the original and modified packets
    difference = xor_bytes(encrypted_data[:2], modified_packet[:2])

    # Ensure decryption_result is of type bytes
    if isinstance(decryption_result, str):
        decryption_result = decryption_result.encode('utf-8')

    # XOR the difference with the decrypted result to obtain the original plaintext
    decrypted_data = xor_bytes(decryption_result, difference)
    
    print(f"Original packet: {encrypted_data}")
    print(f"Modified packet: {modified_packet}")
    print(f"Decryption result: {decryption_result}")
    
    return decrypted_data
def demonstrate_attack(plaintext, password):
    encrypted_data, salt = encrypt(plaintext, password)
    encrypted_data_base64 = base64.b64encode(encrypted_data.encode('utf-8')).decode('utf-8')

    # Attempt to decrypt the encrypted data using the mister_zuccherato_attack function
    decrypted_data = mister_zuccherato_attack(base64.b64decode(encrypted_data_base64),
                                                lambda packet: oracle_decrypt_function(packet, password, salt, True))

    if decrypted_data == plaintext:
        print(f"Attack on OpenPGP-CFB mode was successful! Original plaintext was recovered.")
        return True
    else:
        print(f"Attack on OpenPGP-CFB mode failed. Original plaintext could not be recovered.")
        return False



if __name__ == "__main__":
    plaintext = b'This is a test message. We will demonstrate the attack on OpenPGP-CFB mode.'
    password = "my_password"

    success, attack_time = measure_time(demonstrate_attack, plaintext, password)

    if success:
        print(f"Attack on OpenPGP-CFB mode was successful! Time taken: {attack_time:.4f} seconds")
    else:
        print(f"Attack on OpenPGP-CFB mode failed. Time taken: {attack_time:.4f} seconds")

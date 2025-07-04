from key_generation import generate_keys, logistic_map
from encryption import encrypt
from decryption import decrypt

if __name__ == "__main__":
    # Key generation
    seed1, seed2 = 0.123456, 0.654321
    public_key, private_key = generate_keys(seed1, seed2)
    print("Public Key:", public_key)
    print("Private Key:", private_key)

    # Use the same fractal sequence for both encryption and decryption
    fs = logistic_map(seed1, 3.9, 1000)

    block_size = 8

    # Encryption
    plaintext = input("Enter the plaintext to encrypt: ")
    ciphertext, mac, pad_len = encrypt(plaintext, fs, public_key, block_size=block_size)
    print("Ciphertext blocks:", ciphertext)
    print("MAC:", mac)
    print("Pad length:", pad_len)

    # Decryption
    try:
        decrypted = decrypt(ciphertext, mac, fs, public_key, pad_len, block_size=block_size)
        print("Decrypted text:", decrypted)
    except Exception as e:
        print("Decryption failed:", e) 
import hashlib
from key_generation import logistic_map, fractal_to_binary
from encryption import divide_blocks, xor_blocks

def reverse_permute_blocks(blocks, perm_indices):
    result = [None] * len(blocks)
    for i, idx in enumerate(perm_indices):
        result[idx] = blocks[i]
    return result

def verify_mac(ciphertext, public_key, mac):
    data = ''.join(ciphertext) + public_key
    calc_mac = hashlib.sha512(data.encode()).hexdigest()
    return calc_mac == mac

def decrypt(ciphertext_blocks, mac, fs2, public_key, pad_len=0, block_size=8):
    if not verify_mac(ciphertext_blocks, public_key, mac):
        raise ValueError("MAC verification failed!")
    # Reverse permutation: original was reversed, so reverse again
    perm_indices = list(reversed(range(len(ciphertext_blocks))))
    unpermuted = reverse_permute_blocks(ciphertext_blocks, perm_indices)
    # Ensure mask is long enough
    mask_seq = fractal_to_binary(fs2, bits=block_size)
    while len(mask_seq) < len(unpermuted) * block_size:
        mask_seq += fractal_to_binary(fs2, bits=block_size)
    mask_blocks = divide_blocks(mask_seq, block_size)[:len(unpermuted)]
    # Debug prints
    print("[DEBUG] Decrypt mask blocks:", mask_blocks)
    print("[DEBUG] Decrypt unpermuted blocks:", unpermuted)
    plain_blocks = xor_blocks(unpermuted, mask_blocks)
    # Combine binary blocks and remove padding
    bin_data = ''.join(plain_blocks)
    if pad_len:
        bin_data = bin_data[:-pad_len]
    chars = [chr(int(bin_data[i:i+8], 2)) for i in range(0, len(bin_data), 8)]
    return ''.join(chars)

if __name__ == "__main__":
    # Example usage
    fs2 = logistic_map(0.654321, 3.9, 1000)
    public_key = 'demo_public_key'  # For demo, use same as encryption
    # These should match output from encryption.py
    ciphertext = ['00000000', '00000000']  # Replace with real blocks
    mac = 'demo_mac'  # Replace with real MAC
    pad_len = 0  # Replace with real pad_len
    try:
        plaintext = decrypt(ciphertext, mac, fs2, public_key, pad_len, block_size=8)
        print("Decrypted text:", plaintext)
    except Exception as e:
        print(e) 
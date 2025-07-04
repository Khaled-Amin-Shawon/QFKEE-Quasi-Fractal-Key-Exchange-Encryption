import hashlib
from key_generation import logistic_map, fractal_to_binary

def divide_blocks(data, block_size):
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

def xor_blocks(blocks, mask):
    return [format(int(b, 2) ^ int(m, 2), f'0{len(b)}b') for b, m in zip(blocks, mask)]

def permute_blocks(blocks, perm_indices):
    return [blocks[i] for i in perm_indices]

def compute_mac(ciphertext, public_key):
    data = ''.join(ciphertext) + public_key
    return hashlib.sha512(data.encode()).hexdigest()

def pad_binary(bin_data, block_size):
    pad_len = (block_size - len(bin_data) % block_size) % block_size
    return bin_data + '0' * pad_len, pad_len

def encrypt(plaintext, fs1, public_key, block_size=8):
    # Convert plaintext to binary
    bin_data = ''.join(format(ord(c), '08b') for c in plaintext)
    bin_data, pad_len = pad_binary(bin_data, block_size)
    blocks = divide_blocks(bin_data, block_size)
    # Ensure mask is long enough
    mask_seq = fractal_to_binary(fs1, bits=block_size)
    while len(mask_seq) < len(blocks) * block_size:
        # Extend mask_seq if needed
        mask_seq += fractal_to_binary(fs1, bits=block_size)
    mask_blocks = divide_blocks(mask_seq, block_size)[:len(blocks)]
    # Debug prints
    print("[DEBUG] Plaintext blocks:", blocks)
    print("[DEBUG] Mask blocks:", mask_blocks)
    xored = xor_blocks(blocks, mask_blocks)
    # Simple permutation: reverse order (for demo)
    perm_indices = list(reversed(range(len(xored))))
    permuted = permute_blocks(xored, perm_indices)
    mac = compute_mac(permuted, public_key)
    return permuted, mac, pad_len

if __name__ == "__main__":
    # Example usage
    fs1 = logistic_map(0.123456, 3.9, 1000)
    public_key = 'demo_public_key'
    plaintext = "HELLO"
    ciphertext, mac, pad_len = encrypt(plaintext, fs1, public_key, block_size=8)
    print("Ciphertext blocks:", ciphertext)
    print("MAC:", mac)
    print("Pad length:", pad_len) 
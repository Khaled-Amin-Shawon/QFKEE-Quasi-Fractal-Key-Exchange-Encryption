import hashlib

# Logistic map function
def logistic_map(x0, r, iterations):
    sequence = []
    x = x0
    for _ in range(iterations):
        x = r * x * (1 - x)
        sequence.append(x)
    return sequence

# Convert fractal sequence to binary string
def fractal_to_binary(seq, bits=16):
    return ''.join(format(int(s * (2**bits)), f'0{bits}b') for s in seq)

# Construct a pseudo-prime (for demo, just sum digits and add a large prime)
def construct_quasi_prime(seq, large_prime=32416190071):
    digits = ''.join(str(int(s * 1e6)) for s in seq[:10])
    pseudo_prime = int(digits) | 1  # ensure odd
    return pseudo_prime * large_prime

# Key derivation using SHA-512
def derive_key(fractal_bin, quasi_prime):
    data = fractal_bin + str(quasi_prime)
    return hashlib.sha512(data.encode()).hexdigest()

# Main key generation function
def generate_keys(seed1, seed2, r=3.9, iterations=100):
    fs1 = logistic_map(seed1, r, iterations)
    fs2 = logistic_map(seed2, r, iterations)
    bin1 = fractal_to_binary(fs1)
    bin2 = fractal_to_binary(fs2)
    qp1 = construct_quasi_prime(fs1)
    qp2 = construct_quasi_prime(fs2)
    pk = derive_key(bin1, qp1)
    sk = derive_key(bin2, qp2)
    return pk, sk

if __name__ == "__main__":
    # Example usage
    public_key, private_key = generate_keys(0.123456, 0.654321)
    print("Public Key:", public_key)
    print("Private Key:", private_key) 
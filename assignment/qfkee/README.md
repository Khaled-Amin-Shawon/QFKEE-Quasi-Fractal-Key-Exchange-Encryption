# QFKEE: Quasi-Fractal Key Exchange Encryption - Full Python Implementation

This repository provides a complete, ready-to-use Python implementation of the QFKEE (Quasi-Fractal Key Exchange Encryption) algorithm. QFKEE is a post-quantum cryptographic scheme that utilizes chaotic fractal sequences and quasi-prime construction to generate high-entropy, quantum-resistant keys. The implementation includes all essential cryptographic steps: key generation, encryption, decryption, and a simple GUI for demonstration.

---

## 📁 Directory Structure

- `key_generation.py`  
  Generates high-entropy cryptographic keys using logistic maps and quasi-prime construction.

- `encryption.py`  
  Encrypts plaintext using the generated keys, chaotic masks, and block permutation.

- `decryption.py`  
  Decrypts ciphertext using the same key and mask sequence to recover the original message.

- `qfkee_gui.py`  
  A simple Tkinter-based GUI for interactive encryption and decryption.

- `utils.py`  
  Utility functions for block display and future expansion.

- `README.md`  
  Full documentation and usage instructions (this file).

---

## 🚀 Quick Start

1. **Clone the repository:**
   ```bash
   git clone <repo-url>
   cd assignment/qfkee
   ```

2. **Run the key generation example:**
   ```bash
   python key_generation.py
   ```

3. **Encrypt a message:**
   ```bash
   python encryption.py
   ```

4. **Decrypt a message:**
   ```bash
   python decryption.py
   ```

5. **Try the GUI:**
   ```bash
   python ../qfkee_gui.py
   ```

---

## 📝 Algorithm Overview

QFKEE combines the following cryptographic primitives:
- **Chaotic Map (Logistic Map):** Generates pseudo-random sequences for mask and key material.
- **Quasi-Prime Construction:** Ensures high entropy and unpredictability in key generation.
- **SHA-512 Hashing:** Derives the final key from chaotic and quasi-prime data.
- **XOR Block Cipher:** Lightweight encryption using block-wise XOR with chaotic masks.
- **Permutation:** Adds diffusion by permuting cipher blocks.

---

## 📄 Example Usage

### Key Generation

# AES-128 Implementation in Python with CBC mode and file support

import os
import argparse

# S-box and Inverse S-box tables (full 256 entries)
Sbox = [
    # (256 values as per AES specification)
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

InvSbox = [
    # (256 values as per AES specification)
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
]

# Round constant (Rcon) table
Rcon = [
    0x00,  # Rcon[0] is unused
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36
]

def sub_bytes(state):
    """Apply S-box substitution to each byte of the state."""
    return [Sbox[byte] for byte in state]

def inv_sub_bytes(state):
    """Apply inverse S-box substitution to each byte of the state."""
    return [InvSbox[byte] for byte in state]

def shift_rows(state):
    """Shift the rows of the state to the left."""
    new_state = [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11],
    ]
    return new_state

def inv_shift_rows(state):
    """Shift the rows of the state to the right."""
    new_state = [
        state[0], state[13], state[10], state[7],
        state[4], state[1], state[14], state[11],
        state[8], state[5], state[2], state[15],
        state[12], state[9], state[6], state[3],
    ]
    return new_state

def xtime(a):
    """Perform multiplication by x (i.e., {02}) in GF(2^8)."""
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF

def mul(a, b):
    """Multiply two numbers in GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        carry = a & 0x80
        a = ((a << 1) & 0xFF)
        if carry:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF

def mix_columns(state):
    """Mix the columns of the state."""
    new_state = []
    for i in range(0, 16, 4):
        s0 = state[i]
        s1 = state[i+1]
        s2 = state[i+2]
        s3 = state[i+3]
        new_state.extend([
            mul(s0, 2) ^ mul(s1, 3) ^ s2 ^ s3,
            s0 ^ mul(s1, 2) ^ mul(s2, 3) ^ s3,
            s0 ^ s1 ^ mul(s2, 2) ^ mul(s3, 3),
            mul(s0, 3) ^ s1 ^ s2 ^ mul(s3, 2),
        ])
    return [b & 0xFF for b in new_state]

def inv_mix_columns(state):
    """Inverse mix columns of the state."""
    new_state = []
    for i in range(0, 16, 4):
        s = state[i:i+4]
        new_state.extend([
            mul(s[0], 0x0E) ^ mul(s[1], 0x0B) ^ mul(s[2], 0x0D) ^ mul(s[3], 0x09),
            mul(s[0], 0x09) ^ mul(s[1], 0x0E) ^ mul(s[2], 0x0B) ^ mul(s[3], 0x0D),
            mul(s[0], 0x0D) ^ mul(s[1], 0x09) ^ mul(s[2], 0x0E) ^ mul(s[3], 0x0B),
            mul(s[0], 0x0B) ^ mul(s[1], 0x0D) ^ mul(s[2], 0x09) ^ mul(s[3], 0x0E),
        ])
    return [b & 0xFF for b in new_state]

def add_round_key(state, round_key):
    """Add (XOR) the round key to the state."""
    return [s ^ rk for s, rk in zip(state, round_key)]

def key_expansion(key):
    """Generate the key schedule."""
    Nk = 4  # Key length (in 32-bit words) for AES-128
    Nb = 4  # Block size (in 32-bit words)
    Nr = 10  # Number of rounds for AES-128

    key_symbols = list(key)
    if len(key_symbols) < 16:
        key_symbols += [0x00] * (16 - len(key_symbols))  # Pad key with zeros

    key_schedule = [key_symbols[i:i+4] for i in range(0, len(key_symbols), 4)]

    for i in range(Nk, Nb * (Nr + 1)):
        temp = key_schedule[i - 1][:]
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]  # RotWord
            temp = [Sbox[b] for b in temp]  # SubWord
            temp[0] ^= Rcon[i // Nk]
        key_schedule.append([k ^ t for k, t in zip(key_schedule[i - Nk], temp)])

    return [item for sublist in key_schedule for item in sublist]

def encrypt_block(plaintext, key_schedule):
    """Encrypt a single block of plaintext."""
    state = list(plaintext)
    state = add_round_key(state, key_schedule[:16])

    for round_num in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, key_schedule[round_num*16:(round_num+1)*16])

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, key_schedule[160:])

    return state

def decrypt_block(ciphertext, key_schedule):
    """Decrypt a single block of ciphertext."""
    state = list(ciphertext)
    state = add_round_key(state, key_schedule[160:])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)

    for round_num in range(9, 0, -1):
        state = add_round_key(state, key_schedule[round_num*16:(round_num+1)*16])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)

    state = add_round_key(state, key_schedule[:16])
    return state

# PKCS#7 Padding
def pad(data):
    """Apply PKCS#7 padding to the data."""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    """Remove PKCS#7 padding from the data."""
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_cbc(plaintext, key):
    """Encrypt data using AES in CBC mode."""
    key_schedule = key_expansion(key)
    iv = os.urandom(16)  # Random IV
    ciphertext = iv  # Start with IV

    plaintext_padded = pad(plaintext)
    blocks = [plaintext_padded[i:i+16] for i in range(0, len(plaintext_padded), 16)]
    previous_block = iv

    for block in blocks:
        block = bytes([b1 ^ b2 for b1, b2 in zip(block, previous_block)])
        encrypted_block = encrypt_block(block, key_schedule)
        encrypted_block_bytes = bytes(encrypted_block)
        ciphertext += encrypted_block_bytes
        previous_block = encrypted_block_bytes

    return ciphertext

def decrypt_cbc(ciphertext, key):
    """Decrypt data encrypted using AES in CBC mode."""
    key_schedule = key_expansion(key)
    iv = ciphertext[:16]
    ciphertext_blocks = [ciphertext[i:i+16] for i in range(16, len(ciphertext), 16)]
    plaintext_padded = b''
    previous_block = iv

    for block in ciphertext_blocks:
        decrypted_block = decrypt_block(block, key_schedule)
        decrypted_block_bytes = bytes(decrypted_block)
        plaintext_block = bytes([b1 ^ b2 for b1, b2 in zip(decrypted_block_bytes, previous_block)])
        plaintext_padded += plaintext_block
        previous_block = block

    plaintext = unpad(plaintext_padded)
    return plaintext

def encrypt_file(input_filename, output_filename, key):
    """Encrypt a file using AES in CBC mode."""
    with open(input_filename, 'rb') as f:
        plaintext = f.read()

    ciphertext = encrypt_cbc(plaintext, key)

    with open(output_filename, 'wb') as f:
        f.write(ciphertext)

def decrypt_file(input_filename, output_filename, key):
    """Decrypt a file encrypted using AES in CBC mode."""
    with open(input_filename, 'rb') as f:
        ciphertext = f.read()

    plaintext = decrypt_cbc(ciphertext, key)

    with open(output_filename, 'wb') as f:
        f.write(plaintext)

# Example usage
def main():
    parser = argparse.ArgumentParser(description="AES-128 Encryption/Decryption Tool")
    parser.add_argument("operation", choices=["encrypt", "decrypt"], help="Operation: encrypt or decrypt")
    parser.add_argument("input_file", help="Input file")
    parser.add_argument("output_file", help="Output file")
    parser.add_argument("--key", required=True, help="16-byte key in hex (e.g., 2b7e151628aed2a6abf7158809cf4f3c)")

    args = parser.parse_args()

    key = bytes.fromhex(args.key)

    if len(key) != 16:
        print("Error: Key must be exactly 16 bytes (32 hex characters).")
        return

    if args.operation == "encrypt":
        encrypt_file(args.input_file, args.output_file, key)
        print(f"File encrypted successfully: {args.output_file}")
    elif args.operation == "decrypt":
        decrypt_file(args.input_file, args.output_file, key)
        print(f"File decrypted successfully: {args.output_file}")

if __name__ == "__main__":
    main()


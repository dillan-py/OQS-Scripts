import oqs
import os
import sys
import time
import psutil
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KYBER_ALG = "Kyber1024"

def generate_keys():
    """Generate a Kyber key pair."""
    kem = oqs.KeyEncapsulation(KYBER_ALG)
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    return public_key, secret_key, kem

def measure_memory():
    """Returns memory usage in MB."""
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)

def encrypt_file(input_file, public_key):
    """Encrypts a file using AES-GCM with a Kyber-derived key."""
    kem = oqs.KeyEncapsulation(KYBER_ALG)
    kem.generate_keypair()
    shared_secret, ciphertext = kem.encap_secret(public_key)
    
    aes_key = shared_secret[:32]  # Use the first 32 bytes for AES key
    cipher = AES.new(aes_key, AES.MODE_GCM)
    
    with open(input_file, "rb") as f:
        file_data = f.read()
    
    start_time = time.time()
    start_mem = measure_memory()
    ciphertext_data, tag = cipher.encrypt_and_digest(file_data)
    enc_file = input_file + ".enc"
    
    with open(enc_file, "wb") as f:
        f.write(len(ciphertext).to_bytes(4, "big") + ciphertext + cipher.nonce + tag + ciphertext_data)
    
    end_time = time.time()
    end_mem = measure_memory()
    
    print(f"Encryption Time: {end_time - start_time:.4f} seconds")
    print(f"Memory Used: {end_mem - start_mem:.4f} MB")
    print(f"File encrypted: {enc_file}")
    return ciphertext, enc_file

def decrypt_file(encrypted_file, secret_key, kem):
    """Decrypts a file using AES-GCM with a Kyber-derived key."""
    with open(encrypted_file, "rb") as f:
        data = f.read()
    
    ciphertext_len = int.from_bytes(data[:4], "big")
    ciphertext = data[4:4 + ciphertext_len]
    nonce = data[4 + ciphertext_len:4 + ciphertext_len + 16]
    tag = data[4 + ciphertext_len + 16:4 + ciphertext_len + 32]
    encrypted_data = data[4 + ciphertext_len + 32:]
    
    start_time = time.time()
    start_mem = measure_memory()
    shared_secret = kem.decap_secret(ciphertext)
    aes_key = shared_secret[:32]  # Use the first 32 bytes for AES key
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
    dec_file = encrypted_file.replace(".enc", ".dec")
    
    with open(dec_file, "wb") as f:
        f.write(decrypted_data)
    
    end_time = time.time()
    end_mem = measure_memory()
    
    print(f"Decryption Time: {end_time - start_time:.4f} seconds")
    print(f"Memory Used: {end_mem - start_mem:.4f} MB")
    print(f"File decrypted: {dec_file}")
    return dec_file

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 encrypt.py <file_to_encrypt>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print("Error: File not found.")
        sys.exit(1)
    
    public_key, secret_key, kem = generate_keys()
    ciphertext, enc_file = encrypt_file(input_file, public_key)
    decrypted_file = decrypt_file(enc_file, secret_key, kem)
    
    with open(input_file, "rb") as orig, open(decrypted_file, "rb") as dec:
        assert orig.read() == dec.read(), "Decryption failed! File contents do not match."
        print("Decryption successful. Files match!")

if __name__ == "__main__":
    main()

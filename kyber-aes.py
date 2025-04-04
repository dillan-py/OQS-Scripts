import sys
import time
import psutil
import os
import oqs
import pandas as pd
import io
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def measure_memory():
    return psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024  # In MB

def aes_encrypt(data, key, iv):
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()

def aes_decrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def encapsulate():
    with oqs.KeyEncapsulation("Kyber512") as kem:
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        private_key = kem.export_secret_key()  # Only usable in this session
    return public_key, private_key, ciphertext, shared_secret

def encrypt_file(input_path, output_path, key):
    iv = os.urandom(16)
    df = pd.read_excel(input_path)
    data = df.to_csv(index=False).encode()

    start_time = time.time()
    mem_before = measure_memory()

    encrypted = aes_encrypt(data, key, iv)

    mem_after = measure_memory()
    end_time = time.time()

    with open(output_path, 'wb') as f:
        f.write(iv + encrypted)

    return end_time - start_time, mem_after - mem_before

def decrypt_file(input_path, output_path, key):
    with open(input_path, 'rb') as f:
        iv = f.read(16)
        encrypted = f.read()

    start_time = time.time()
    mem_before = measure_memory()

    decrypted = aes_decrypt(encrypted, key, iv)

    mem_after = measure_memory()
    end_time = time.time()

    df = pd.read_csv(io.StringIO(decrypted.decode()))
    df.to_excel(output_path, index=False)

    return end_time - start_time, mem_after - mem_before, df

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 encrypt.py <file.xlsx>")
        return

    input_file = sys.argv[1]
    encrypted_file = "encrypted_output.bin"
    decrypted_file = "decrypted_output.xlsx"

    print("\n[*] Performing PQ key encapsulation...")
    start = time.time()
    public_key, private_key, ciphertext, shared_secret = encapsulate()
    encaps_time = time.time() - start
    print("[+] Encapsulation complete.")

    aes_key = shared_secret[:32]  # AES-256 key from shared secret

    print("\n[*] Encrypting file with AES-256...")
    encrypt_time, encrypt_mem = encrypt_file(input_file, encrypted_file, aes_key)
    print("[+] Encryption complete.")

    print("\n[*] Decrypting file with AES-256...")
    decrypt_time, decrypt_mem, df = decrypt_file(encrypted_file, decrypted_file, aes_key)
    print("[+] Decryption complete.")

    print("\n--- Evaluation Metrics ---")
    print(f"Encapsulation Time:      {encaps_time:.4f} s")
    print(f"Encryption Time:         {encrypt_time:.4f} s")
    print(f"Encryption Memory Used:  {encrypt_mem:.2f} MB")
    print(f"Decryption Time:         {decrypt_time:.4f} s")
    print(f"Decryption Memory Used:  {decrypt_mem:.2f} MB")

    print("\n--- Decrypted File Preview ---")
    print(df.head())

if __name__ == "__main__":
    main()

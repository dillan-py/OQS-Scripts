import sys
import time
import psutil
import os
import oqs
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import pandas as pd
import io

def measure_memory():
    return psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024  # MB

def aes_encrypt(data, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def encapsulate():
    with oqs.KeyEncapsulation("Kyber512") as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        ciphertext, shared_secret = kem.encap_secret(public_key)
    return public_key, private_key, ciphertext, shared_secret

def decapsulate(ciphertext, private_key):
    with oqs.KeyEncapsulation("Kyber512") as kem:
        kem.generate_keypair()  # Initializes internal state
        kem.import_secret_key(private_key)
        shared_secret = kem.decap_secret(ciphertext)
    return shared_secret

def encrypt_file(input_file, encrypted_file, key):
    iv = os.urandom(16)

    # Load XLSX file into bytes (via CSV to simplify AES encoding)
    df = pd.read_excel(input_file)
    data = df.to_csv(index=False).encode()

    enc_start = time.time()
    mem_before = measure_memory()
    encrypted_data = aes_encrypt(data, key, iv)
    mem_after = measure_memory()
    enc_end = time.time()

    with open(encrypted_file, 'wb') as f:
        f.write(iv + encrypted_data)

    return enc_end - enc_start, mem_after - mem_before

def decrypt_file(encrypted_file, decrypted_file, key):
    with open(encrypted_file, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()

    dec_start = time.time()
    mem_before = measure_memory()
    decrypted_data = aes_decrypt(encrypted_data, key, iv)
    mem_after = measure_memory()
    dec_end = time.time()

    # Convert back from CSV to DataFrame
    df = pd.read_csv(io.StringIO(decrypted_data.decode()))
    df.to_excel(decrypted_file, index=False)

    return dec_end - dec_start, mem_after - mem_before, df

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 encrypt.py <file.xlsx>")
        return

    input_file = sys.argv[1]
    encrypted_file = "encrypted_file.bin"
    decrypted_file = "decrypted_file.xlsx"

    print("[*] Starting key encapsulation...")
    start = time.time()
    public_key, private_key, ciphertext, shared_secret = encapsulate()
    encaps_time = time.time() - start
    print("[+] Encapsulation complete.")

    aes_key = shared_secret[:32]  # Use first 32 bytes of shared secret as AES-256 key

    print("[*] Encrypting file...")
    enc_time, enc_mem = encrypt_file(input_file, encrypted_file, aes_key)
    print("[+] File encrypted.")

    print("[*] Starting decapsulation...")
    start = time.time()
    decapsulated_secret = decapsulate(ciphertext, private_key)
    decaps_time = time.time() - start
    print("[+] Decapsulation complete.")

    dec_key = decapsulated_secret[:32]

    print("[*] Decrypting file...")
    dec_time, dec_mem, df = decrypt_file(encrypted_file, decrypted_file, dec_key)
    print("[+] File decrypted.")

    print("\n--- Evaluation Metrics ---")
    print(f"Encapsulation Time:     {encaps_time:.4f} s")
    print(f"Encryption Time:        {enc_time:.4f} s")
    print(f"Encryption Memory:      {enc_mem:.2f} MB")
    print(f"Decapsulation Time:     {decaps_time:.4f} s")
    print(f"Decryption Time:        {dec_time:.4f} s")
    print(f"Decryption Memory:      {dec_mem:.2f} MB")

    print("\n--- Decrypted File Preview ---")
    print(df.head())

if __name__ == "__main__":
    main()

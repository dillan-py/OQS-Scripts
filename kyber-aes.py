import oqs
import os
import sys
import time
import csv
import psutil  # For memory usage
import pandas as pd
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.cmac import CMAC
import base64

KYBER_ALG = "Kyber1024"
AES_KEY_SIZE = 32  # 256-bit AES key
NONCE_SIZE = 12  # GCM nonce size


def generate_keys():
    """Generate a Kyber key pair (public and secret keys)."""
    kem = oqs.KeyEncapsulation(KYBER_ALG)
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    return public_key, secret_key, kem


def derive_aes_key(shared_secret):
    """Derive a 256-bit AES key using HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=b"kyber-aes-key",
        backend=default_backend(),
    )
    return hkdf.derive(shared_secret)


def encrypt_file(input_file, public_key):
    """Encrypt a file using AES-GCM and encapsulate the key with Kyber."""
    kem = oqs.KeyEncapsulation(KYBER_ALG)
    kem.generate_keypair()
    
    # Kyber key encapsulation
    start_encap_time = time.time()
    shared_secret, ciphertext = kem.encap_secret(public_key)
    end_encap_time = time.time()
    encapsulation_time = end_encap_time - start_encap_time
    
    aes_key = derive_aes_key(shared_secret)
    
    # Generate a random nonce
    nonce = os.urandom(NONCE_SIZE)
    
    # Read file contents
    with open(input_file, "rb") as f:
        file_data = f.read()
    
    # AES encryption
    start_encryption_time = time.time()
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()
    end_encryption_time = time.time()
    encryption_time = end_encryption_time - start_encryption_time
    
    # Save encrypted file
    enc_file = input_file + ".enc"
    with open(enc_file, "wb") as f:
        f.write(len(ciphertext).to_bytes(4, "big") + ciphertext + nonce + encryptor.tag + encrypted_data)
    
    memory_usage = psutil.Process(os.getpid()).memory_info().rss / (1024 ** 2)
    
    print(f"File encrypted: {enc_file}")
    return ciphertext, enc_file, encapsulation_time, encryption_time, memory_usage


def decrypt_file(encrypted_file, secret_key, kem):
    """Decrypt a file using AES-GCM and the Kyber-decapsulated key."""
    with open(encrypted_file, "rb") as f:
        data = f.read()
    
    ciphertext_len = int.from_bytes(data[:4], "big")
    ciphertext = data[4:4 + ciphertext_len]
    nonce = data[4 + ciphertext_len: 4 + ciphertext_len + NONCE_SIZE]
    tag = data[4 + ciphertext_len + NONCE_SIZE: 4 + ciphertext_len + NONCE_SIZE + 16]
    encrypted_data = data[4 + ciphertext_len + NONCE_SIZE + 16:]
    
    # Kyber key decapsulation
    start_decap_time = time.time()
    shared_secret = kem.decap_secret(ciphertext)
    end_decap_time = time.time()
    decapsulation_time = end_decap_time - start_decap_time
    
    aes_key = derive_aes_key(shared_secret)
    
    # AES decryption
    start_decryption_time = time.time()
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    end_decryption_time = time.time()
    decryption_time = end_decryption_time - start_decryption_time
    
    # Save decrypted file
    dec_file = encrypted_file.replace(".enc", ".dec")
    with open(dec_file, "wb") as f:
        f.write(decrypted_data)
    
    print(f"File decrypted: {dec_file}")
    return decapsulation_time, decryption_time


def process_csv(csv_file):
    """Process files specified in an Excel or CSV file."""
    try:
        if csv_file.endswith(".xlsx"):
            df = pd.read_excel(csv_file, engine="openpyxl")
            df.columns = df.columns.str.strip()
            temp_csv = csv_file.replace(".xlsx", ".csv")
            df.to_csv(temp_csv, index=False)
            csv_file = temp_csv

        with open(csv_file, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            fieldnames = [name.strip() for name in reader.fieldnames if name]

            if "input_file" not in fieldnames:
                print(f"Error: 'input_file' column not found. Available columns: {fieldnames}")
                return

            for row in reader:
                input_file = row.get("input_file", "").strip()
                if not input_file or not os.path.exists(input_file):
                    print(f"Error: File '{input_file}' not found.")
                    continue

                public_key, secret_key, kem = generate_keys()
                ciphertext, enc_file, encap_time, enc_time, mem_usage = encrypt_file(input_file, public_key)
                print(f"Encapsulation Time: {encap_time} s, Encryption Time: {enc_time} s, Memory Usage: {mem_usage} MB")
                
                decap_time, dec_time = decrypt_file(enc_file, secret_key, kem)
                print(f"Decapsulation Time: {decap_time} s, Decryption Time: {dec_time} s")
    except UnicodeDecodeError:
        print("Error: Failed to decode the CSV file. Retrying with ISO-8859-1 encoding...")
        process_csv_with_encoding(csv_file, "ISO-8859-1")


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 encrypt.py <csv_file>")
        sys.exit(1)

    csv_file = sys.argv[1]
    if not os.path.exists(csv_file):
        print("Error: CSV file not found.")
        sys.exit(1)

    process_csv(csv_file)


if __name__ == "__main__":
    main()

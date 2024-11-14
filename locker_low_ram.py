import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import urlsafe_b64encode, urlsafe_b64decode
import platform
import multiprocessing
import psutil
import tkinter as tk
from tkinter import filedialog

def get_chunk_size():
    total_memory = psutil.virtual_memory().total
    chunk_size = total_memory // 15
    return chunk_size

CHUNK_SIZE = get_chunk_size()
print(f"Chunk Size: {CHUNK_SIZE} bytes ({CHUNK_SIZE / (1024**2):.2f} MB)")

def get_cpu_description():
    return platform.processor()

def get_cpu_model():
    return cpuinfo.get_cpu_info()["brand_raw"]

def encrypt_rsa(data, public_key):
    public_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

def encrypt_aes_chunk(chunk, key, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    ciphertext = cipher.encrypt(chunk)
    return ciphertext

def decrypt_rsa(data, priv_key):
    with open(priv_key, 'rb') as key_file:
        private_key = RSA.import_key(key_file.read())
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(data)

def decrypt_aes_chunk(chunk, key, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(chunk)

def encrypt_filename(filename, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(filename.encode('utf-8'))
    return urlsafe_b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_filename(enc_filename, key):
    data = urlsafe_b64decode(enc_filename)
    nonce = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

def encrypt_file(file_path, public_key):
    key = get_random_bytes(32)
    public_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(key)
    
    folder_path = os.path.dirname(file_path)
    original_filename = os.path.basename(file_path)
    enc_filename = encrypt_filename(original_filename, key)
    enc_file_path = os.path.join(folder_path, enc_filename + ".enc")

    with open(file_path, 'rb') as file, open(enc_file_path, 'wb') as enc_file:
        enc_file.write(encrypted_key)
        nonce = get_random_bytes(16)
        enc_file.write(nonce)
        while chunk := file.read(CHUNK_SIZE):
            enc_chunk = encrypt_aes_chunk(chunk, key, nonce)
            enc_file.write(enc_chunk)

    os.remove(file_path)
    print(f"Encrypted {file_path} to {enc_file_path}")

def decrypt_file(file_path, priv_key, bytes_calculated):
    with open(file_path, 'rb') as enc_file:
        enc_key = enc_file.read(bytes_calculated)
        nonce = enc_file.read(16)
        
        key = decrypt_rsa(enc_key, priv_key)
        
        folder_path = os.path.dirname(file_path)
        enc_filename = os.path.basename(file_path).replace('.enc', '')
        original_filename = decrypt_filename(enc_filename, key)
        dec_file_path = os.path.join(folder_path, original_filename)

        with open(dec_file_path, 'wb') as dec_file:
            while chunk := enc_file.read(CHUNK_SIZE):
                dec_chunk = decrypt_aes_chunk(chunk, key, nonce)
                dec_file.write(dec_chunk)

    os.remove(file_path)
    print(f"Decrypted {file_path} to {dec_file_path}")

def process_file(file_path, public_key, priv_key, bytes_calculated, action):
    if action == 'decrypt' and file_path.endswith('.enc'):
        decrypt_file(file_path, priv_key, bytes_calculated)
    elif action == 'encrypt' and not file_path.endswith('.enc'):
        encrypt_file(file_path, public_key)

def run_process_directory(directory, public_key, priv_key, num_processes, bytes_calculated, action):
    pool = multiprocessing.Pool(num_processes)
    for root, _, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            pool.apply_async(process_file, (file_path, public_key, priv_key, bytes_calculated, action))
    pool.close()
    pool.join()

if __name__ == "__main__":
    print("Hello and welcome to Jimmy's secured decrypter/encrypter")
    print("This is a locker which is encrypting all your files in this folder so no one can steal your data.")
    version_check = input("Press any key to continue... ")
    if version_check == "--version":
        print("This is Version 1.1")
        input("Press any key to continue... ")

    action = ''
    while action not in ['encrypt', 'decrypt']:
        action = input("Do you want to encrypt or decrypt the files? (enter 'encrypt' or 'decrypt'): ").strip().lower()

    root = tk.Tk()
    root.withdraw()  # Versteckt das Hauptfenster
    folder = filedialog.askdirectory(title="Select folder to encrypt/decrypt")
    if not folder:
        print("No folder selected. Exiting...")
        exit()

    with open('key_length.txt', 'r') as file:
        content = file.read()
    bytes_read = int(content)
    bytes_calculated = int(bytes_read / 8)

    cpu_description = get_cpu_description()
    print("Your CPU description: " + cpu_description)
    print("Available CPU cores: " + str(multiprocessing.cpu_count()))

    while True:
        try:
            num_processes = input("Please enter the number of CPU cores you want to utilize: ")
            if num_processes.strip() == '':
                raise ValueError("Input cannot be empty.")
            num_processes = int(num_processes)
            if num_processes > 0 and num_processes <= multiprocessing.cpu_count():
                break
            else:
                print(f"Please enter a number between 1 and {multiprocessing.cpu_count()}.")
        except ValueError as e:
            print(f"Invalid input. Please enter a valid number. {e}")

    priv_key_path = 'priv.key'
    pub_key_path = 'pub.key'

    if os.path.isfile(priv_key_path) and os.path.isfile(pub_key_path):
        with open(pub_key_path, 'r') as file:
            public_key = file.read()
        run_process_directory(folder, public_key, priv_key_path, num_processes, bytes_calculated, action)
    else:
        if not os.path.isfile(priv_key_path):
            print("Private key file 'priv.key' not found.")
        if not os.path.isfile(pub_key_path):
            print("Public key file 'pub.key' not found.")

    print("Process finished.")
    input("...")

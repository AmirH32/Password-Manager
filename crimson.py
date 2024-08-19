#!/usr/bin/env python3
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from fuzzywuzzy import process 
import getpass
import pyperclip
import time
import sys


BACKEND = default_backend()
SALT_SIZE = 16  # 128-bit salt
KEY_SIZE = 32  # 256-bit key
NONCE_SIZE = 12  # 96-bit nonce
TAG_SIZE = 16
ITERATIONS = 100000
FILE_PATH = "/path/to/file"


def secure_delete(file_path, passes=3):
    """Securely delete a file by overwriting it with random data multiple times."""
    with open(file_path, 'ba+', buffering=0) as f:
        length = f.tell()
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(length))
    os.remove(file_path)

def find_closest_string(target, string_list):
    closest_match = process.extractOne(target, string_list)
    if closest_match:
        return closest_match[0]
    else:
        print("There are no passwords use Adder to add some!\nQuitting!")  
        time.sleep(3)      
        quit()

def get_file_name(file_path):
    # Finds the position of the last '/'
    position_index = file_path.rfind('/')
    
    # If '/' is not found, return the whole string
    if position_index == -1:
        return file_path
    
    # Extract substring from the end to the first '/' (excluding) found
    return file_path[position_index + 1:]

class Encryptor:
    @staticmethod
    def generate_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=ITERATIONS,
            backend=BACKEND
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_file(file_path, password):
        """Encrypt the file and save it with .enc extension."""
        salt = os.urandom(SALT_SIZE)
        key = Encryptor.generate_key(password, salt)
        nonce = os.urandom(NONCE_SIZE)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=BACKEND
        )
        
        encryptor = cipher.encryptor()
        
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        with open(file_path + '.enc', 'wb') as f:
            f.write(salt + nonce + encryptor.tag + ciphertext)

        secure_delete(file_path)

        filename = get_file_name(file_path)
        
        print(f"File {filename} encrypted successfully and plaintext deleted.")

    @staticmethod
    def decrypt_file(file_path, password):
        """Decrypt the file and save the result without .enc extension."""
        with open(file_path, 'rb') as f:
            salt = f.read(SALT_SIZE)
            nonce = f.read(NONCE_SIZE)
            tag = f.read(TAG_SIZE)
            ciphertext = f.read()
        
        key = Encryptor.generate_key(password, salt)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=BACKEND
        )
        
        decryptor = cipher.decryptor()
        
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            print(f"Decryption failed: {e}")
            raise Exception
        
        with open(file_path.replace('.enc', ''), 'wb') as f:
            f.write(plaintext)

        filename = get_file_name(file_path)
        
        print(f"File {filename} decrypted successfully.")
        return True
    
def get_master_pass():
    while True:
        password = getpass.getpass(prompt="Set your master password (main password to decrypt text file):")
        confirm_password = getpass.getpass(prompt="Confirm your master password:")
        if password == confirm_password:
            return password
        else:
            print("Password and confirmed password are not the same")


def auth_decrypt():
    """Decrypts the file after the correct password is entered otherwise terminates the program"""
    count = 0
    valid = False

    ### Checks if file passwords file doesnt exist at all
    if not os.path.isfile(FILE_PATH) and not os.path.isfile(FILE_PATH+'.enc'):
        print(f"{FILENAME} file not found >>>\nCreating a {FILENAME} file for you...")
        with open(FILE_PATH, 'w') as f:
            pass
        password = get_master_pass()
        Encryptor.encrypt_file(FILE_PATH, password)
    ### Checks if you have an unencrypted file
    elif os.path.isfile(FILE_PATH):
        print("Found an unencrypted {FILENAME} text file storing the passwords!")
        password = get_master_pass()
        Encryptor.encrypt_file(FILE_PATH, password)
        print("===Successfully recovered {FILENAME} file and encrypted it===")

        
    while count < 3 and valid == False:
        password = getpass.getpass(prompt='Enter password to open encrypted file: ')
        try:
            valid = Encryptor.decrypt_file(FILE_PATH+'.enc', password)
        except Exception as e:
            print(f"Incorrect password: {e}")
            count += 1
    if count == 3:
        quit()

def file_reader(file_path):
    with open(file_path, "r") as file:
    #Read all the lines from the file
        lines = [line.strip() for line in file]
    return lines

def text_parser(lines):
    string_list = lines
    before_comma = [s.split(',')[0].strip() for s in string_list]
    after_comma = [s.split(',', 1)[1].strip() for s in string_list]
    return before_comma, after_comma
    
if __name__ == "__main__":
    FILENAME = get_file_name(FILE_PATH)


    print(f'IF YOU WANT TO ADD PASSWORDS QUICKLY \n1).CREATE A "{FILENAME}" text file or just "{FILENAME[:-4]}" (on windows)\n2).Insert passwords in the format "label,password" (no spaces) and seperate each entry with a new line\n3).Open either Adder or Crimson\nOr simply just use the adder program and add them 1 by 1\nTIP - Make sure adder and crimson are in the same folder preferably a designated passwords folder\nIf you would like to make the program more secure change the FILE_PATH in source code and follow instructions in github readme')
    print("\n"*3+"Resuming program...")
    auth_decrypt()
    lines = file_reader(FILE_PATH)
    before_comma, after_comma = text_parser(lines)
    try:
        # Doesn't need to re-encrypt as it doesn't make any changes
        secure_delete(FILE_PATH)
        print("Plaintext file deleted, now encrypted") 
    except:
        pass
    while True:
        print(f"List of accounts: \n {before_comma} \n {'='*30}")
        target_string = input("Please enter what you want:")
        closest = find_closest_string(target_string, before_comma)

        index = before_comma.index(closest)
        print(f"Your password is {after_comma[index]} it is saved to your clipboard")
        print(f"Password for {before_comma[index]}")
        pyperclip.copy(after_comma[index])
        

        choice = int(input("Menu\n1). Get another password\n2). Quit\n:"))
        if choice == 1:
            pass
        elif choice == 2:
            quit()
        else:
            pass
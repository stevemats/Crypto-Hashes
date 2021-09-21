#!/usr/bin/env/python3
from __future__ import print_function

import hashlib

print("""

    __  __           __       ______                           __            
   / / / /___ ______/ /_     / ____/__  ____  ___  _________ _/ /_____  _____
  / /_/ / __ `/ ___/ __ \   / / __/ _ \/ __ \/ _ \/ ___/ __ `/ __/ __ \/ ___/
 / __  / /_/ (__  ) / / /  / /_/ /  __/ / / /  __/ /  / /_/ / /_/ /_/ / /    
/_/ /_/\__,_/____/_/ /_/   \____/\___/_/ /_/\___/_/   \__,_/\__/\____/_/     
                                                                             
 [x] Developed by: Stevematindi
 [x] Main Purpose: Crypto Hashing Use case     
 [x] Usage Demo  : $ python generate_hash.py                                                            
""")


def main():
    txt = "Welcome to Hash Generator! Choose one of the hash algorithms below to continue:".title()
    print(txt)
    print('\n1. Generate MD5 hash')
    print('2. Generate SHA1 hash')
    print('3. Generate SHA224 hash') 
    print('4. Generate SHA256 hash') 
    print('5. Generate SHA512 hash') 
    print('6. Generate blake2b hash')
    print ('7. Generate blake2s hash') 
    print('8. Exit')
    while True:
        try:
            choice = int(input('Enter choice: '))
            if choice == 1:
                md5_gen()
                break
            elif choice == 2:
                sha1_gen()
                break
            elif choice == 3:
                sha224_gen()
                break
            elif choice == 4:
                sha256_gen()
                break
            elif choice == 5:
                sha512_gen()
                break
            elif choice == 6:
                blake2b_gen()
                break
            elif choice == 7:
                blake2s_gen()
                break
            elif choice == 8:
                print('\n Program exited!')
                break
            else:
                print("Invalid choice. Enter a choice in menu. 1 ≦ option ≦ 8")
                main()
        except ValueError:
            print("Invalid choice.")
    exit()

#TO DO: Declare a global var for the message

def md5_gen():

    """
    Calculate MD5 hash:

    Note- hashlib.md5() function takes bytes as input hence, we
    are encoding the message to get bytes and providing the encoded 
    message
    """
    user_message = input("Enter message to encrypt: ")
    message = user_message.encode('utf-8')
    message_hash = hashlib.md5(message).digest()
    print("\nHash(byte format)= ",message_hash,"\n")
    message_hash = hashlib.md5(message).hexdigest()
    print("Hash(hexadecimal format)= ", message_hash,"\n")

def sha1_gen():
    """
    SHA-1 is a cryptographic hash function that takes
    a message of arbitrary length as input and generates
    a hash value that is 160-bit in size. 
    """
    user_message = input("Enter message to encrypt: ")
    message = user_message.encode('utf-8')
    message_hash = hashlib.sha1(message).digest()
    print("\nHash(byte format)= ", message_hash,"\n")
    message_hash = hashlib.sha1(message).hexdigest()
    print("Hash(hexadecimal format)= ", message_hash,"\n")


def sha224_gen():
    """
    SHA-224 is intended to provide 112 bits of security, 
    which is the generally accepted strength of Triple-DES [3DES]. 
    """
    user_message = input("Enter message to encrypt: ")
    message = user_message.encode('utf-8')
    message_hash = hashlib.sha224(message).digest()
    print("\nHash(byte format)= ", message_hash,"\n")
    message_hash = hashlib.sha224(message).hexdigest()
    print("Hash(hexadecimal format)= ", message_hash,"\n")


def sha256_gen():
    """
    SHA-256 is a cryptographic hash function that
    takes a message of any length as input and generates
    a hash value that is 256-bit in size.
    """
    user_message = input("Enter message to encrypt: ")
    message = user_message.encode('utf-8')
    message_hash = hashlib.sha256(message).digest()
    print("\nHash(byte format)= ", message_hash,"\n","\n")
    message_hash = hashlib.sha256(message).hexdigest()
    print("Hash(hexadecimal format)= ", message_hash,"\n")

def sha512_gen():
    """
    SHA-512 takes a message of arbitrary length as
    input and generates a hash value that is 512-bit in size. 
    """
    user_message = input("Enter message to encrypt: ")
    message = user_message.encode()
    message_hash = hashlib.sha512(message).digest()
    print("\nHash(byte format)= ",message_hash,"\n")
    message_hash = hashlib.sha512(message).hexdigest()
    print("Hash(hexadecimal format)= ",message_hash,"\n")

def blake2b_gen():
        """
        BLAKE2 is a cryptographic hash function faster than 
        MD5, SHA-1, SHA-2, and SHA-3, yet is at least as secure
        as the latest standard SHA-3
        """
        user_message = input("Enter message to encrypt: ")
        message = user_message.encode()
        message_hash = hashlib.blake2b(message).digest()
        print("\nHash(byte format)= ",message_hash,"\n")
        message_hash = hashlib.blake2b(message).hexdigest()
        print("Hash(hexadecimal format)= ",message_hash,"\n")

def blake2s_gen():
        """
        BLAKE2s is optimized for 8- to 32-bit platforms and 
        produces digests of any size between 1 and 32 bytes. 
        """
        user_message = input("Enter message to encrypt: ")
        message = user_message.encode()
        message_hash = hashlib.blake2s(message).digest()
        print("\nHash(byte format)= ",message_hash,"\n")
        message_hash = hashlib.blake2s(message).hexdigest()
        print("Hash(hexadecimal format)= ",message_hash,"\n")


if __name__ == '__main__':
    main()

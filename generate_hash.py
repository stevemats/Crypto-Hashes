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
    print('\n1. Generate MD5 hash')
    print('2. Generate SHA1 hash')
    print('3. Generate SHA256 hash')
    print('4. Generate SHA512 hash')
    print('5. Exit')
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
                sha256_gen()
                break
            elif choice == 4:
                sha512_gen()
                break
            elif choice == 5:
                break
            else:
                print("Invalid choice. Enter a choice in menu. 1, 2 or 3")
                main()
        except ValueError:
            print("Invalid choice. Enter 1, 2 or 3")
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
    print("Here's your MD5 encoded message (byte format): ",message_hash)
    message_hash = hashlib.md5(message).hexdigest()
    print("Here's your MD5 encoded message (hexadecimal format): ", message_hash)


def sha1_gen():
    """
    SHA-1 is a cryptographic hash function that takes
    a message of arbitrary length as input and generates
    a hash value that is 160-bit in size. Using the hashlib
    module in Python, we can generate the SHA-1 hash of a message
    in the following way:
    """
    user_message = input("Enter message to encrypt: ")
    message = user_message.encode('utf-8')
    message_hash = hashlib.sha1(message).digest()
    print("Here's your SHA1 encoded message (byte format): ", message_hash)
    message_hash = hashlib.sha1(message).hexdigest()
    print("Here's your SHA1 encoded message (hexadecimal format): ", message_hash)


def sha256_gen():
    """
    SHA-256 is a cryptographic hash function that
    takes a message of any length as input and generates
    a hash value that is 256-bit in size. Using the hashlib
    module in Python, we can compute the SHA-256 hash value
    of a message in the following way:
    """
    user_message = input("Enter message to encrypt: ")
    message = user_message.encode('utf-8')
    message_hash = hashlib.sha256(message).digest()
    print("Here's your SHA1 encoded message (byte format): ", message_hash)
    message_hash = hashlib.sha256(message).hexdigest()
    print("Here's your SHA1 encoded message (hexadecimal format): ", message_hash)

def sha512_gen():
    """
    SHA-512 takes a message of arbitrary length as
    input and generates a hash value that is 512-bit in size. 
    We can use the hashlib module in Python to generate the SHA-512
    hash of a message in the following way:
    """
    user_message = input("Enter message to encrypt: ")
    message = user_message.encode()
    message_hash = hashlib.sha512(message).digest()
    print("Here's your SHA1 encoded message (byte format): ",message_hash)
    message_hash = hashlib.sha512(message).hexdigest()
    print("Here's your SHA1 encoded message (hexadecimal format): ",message_hash)


if __name__ == '__main__':
    main()

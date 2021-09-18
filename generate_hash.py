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
    print('2. Exit')
    while True:
        try:
            choice = int(input('Enter choice: '))
            if choice == 1:
                md5_gen()
                break
            elif choice == 2:
                break
            else:
                print("Invalid choice. Enter a choice in menu. 1 or 2")
                main()
        except ValueError:
            print("Invalid choice. Enter 1 or 2")
    exit()


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


if __name__ == '__main__':
    main()

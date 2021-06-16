import hashlib

"""
   SHA-1 is a cryptographic hash function that takes
   a message of arbitrary length as input and generates
   a hash value that is 160-bit in size. Using the hashlib
   module in Python, we can generate the SHA-1 hash of a message
   in the following way:
"""
message = "Hello".encode()
message_hash = hashlib.sha1(message).digest()
print(message_hash)
message_hash = hashlib.sha1(message).hexdigest()
print(message_hash)
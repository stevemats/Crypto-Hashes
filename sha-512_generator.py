import hashlib

"""
 SHA-512 takes a message of arbitrary length as
 input and generates a hash value that is 512-bit in size. 
 We can use the hashlib module in Python to generate the SHA-512
 hash of a message in the following way:
"""
message = "Hello".encode()
message_hash = hashlib.sha512(message).digest()
print(message_hash)
message_hash = hashlib.sha512(message).hexdigest()
print(message_hash)
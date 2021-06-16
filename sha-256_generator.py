import hashlib

"""
  SHA-256 is a cryptographic hash function that
  takes a message of any length as input and generates
  a hash value that is 256-bit in size. Using the hashlib
  module in Python, we can compute the SHA-256 hash value
  of a message in the following way:
"""
message = "Hello".encode()
message_hash = hashlib.sha256(message).digest()
print(message_hash)
message_hash = hashlib.sha256(message).hexdigest()
print(message_hash)

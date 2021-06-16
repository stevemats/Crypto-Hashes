import hashlib

"""
Calculate MD5 hash:

Note- hashlib.md5() function takes bytes as input hence, we
are encoding the message to get bytes and providing the encoded 
message
"""
message = "Hello".encode()
message_hash = hashlib.md5(message).digest()
print(message_hash)
message_hash = hashlib.md5(message).hexdigest()
print(message_hash)

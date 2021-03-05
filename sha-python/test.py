#!/usr/bin/env python

import hashlib
import sys

def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update("TEST")
    return sha256.hexdigest()
    


def main():
    for f in sys.argv[1:]:
        checksum = sha256_checksum(f)
        print(f + '\t' + checksum)
        


def encrypt_string(hash_string):
    sha_signature = \
        hashlib.sha256(hash_string.encode()).hexdigest()
    return sha_signature
hash_string = "Let us test the Binary"
sha_signature = encrypt_string(hash_string)

print(sha_signature)


#sha256 = hashlib.sha256(hash_string.hash_string.encode().hexdigest())
#sha256.update("Hello world This is testing code")
#print(sha256.hexdigest())

if __name__ == '__main__':
    print("main functin")
    main()

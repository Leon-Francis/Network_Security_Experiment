'''
Author: Leon-Francis
Date: 2021-07-08 22:11:34
Contact: leon_francis@163.com
LastEditTime: 2021-07-08 23:59:29
LastEditors: Leon-Francis
Description: 
FilePath: /Network_Security_Experiment/test.py
(C)Copyright 2020-2021, Leon-Francis
'''
from crypto import get_RSA_keys, get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

private_key, public_key = get_RSA_keys()
print(public_key)
print(len(private_key))
print(len(public_key))

AES_key = get_random_bytes(64)

publicKey = RSA.import_key(public_key)
cipher = PKCS1_OAEP.new(publicKey)
encrypted_key = cipher.encrypt(AES_key)
print(encrypted_key)
print(len(encrypted_key))

privateKey = RSA.import_key(private_key)
cipher = PKCS1_OAEP.new(privateKey)
data = cipher.decrypt(encrypted_key)
print(data)

privateKey = RSA.import_key(private_key)
digest = SHA256.new()
digest.update(AES_key)
signer = PKCS1_v1_5.new(privateKey)
print(digest)
signature = signer.sign(digest)
print(signature)
print(len(signature))


publicKey = RSA.import_key(public_key)
PKCS1_v1_5.new(publicKey).verify(digest, signature)

with open('AES_key', 'rb') as f:
    AES_key = f.read()

cipher = AES.new(AES_key, AES.MODE_EAX)

print(len(cipher.nonce))

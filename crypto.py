'''
Author: Leon-Francis
Date: 2021-07-08 21:35:35
Contact: leon_francis@163.com
LastEditTime: 2021-07-09 00:39:40
LastEditors: Leon-Francis
Description: encrypt and decrypt
FilePath: /Network_Security_Experiment/crypto.py
(C)Copyright 2020-2021, Leon-Francis
'''
import random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
import sys

MSG_HEADER_LEN = 10


def get_RSA_keys():
    key = RSA.generate(1024)
    return key.export_key(), key.publickey().export_key()


def get_msg_len(msg):
    msg_len = str(len(msg))
    return msg_len.zfill(MSG_HEADER_LEN)


def crypto_encode(msg, my_private_key, other_pub_key):
    with open('AES_key', 'rb') as f:
        AES_key = f.read()
    cipher = AES.new(AES_key, AES.MODE_EAX)
    msg = msg.encode('utf-8')
    digest = SHA256.new()
    digest.update(msg)
    privateKey = RSA.import_key(my_private_key)
    signer = PKCS1_v1_5.new(privateKey)
    signature = signer.sign(digest)
    encrypt_msg = cipher.encrypt(msg + signature)
    return encrypt_msg, cipher.nonce


def crypto_decode(encrypt_msg, private_key, other_pub_key, nonce):
    with open('AES_key', 'rb') as f:
        AES_key = f.read()
    cipher = AES.new(AES_key, AES.MODE_EAX, nonce=nonce)
    msg_sign = cipher.decrypt(encrypt_msg)
    msg = msg_sign[:-128]
    signature = msg_sign[-128:]
    digest = SHA256.new()
    digest.update(msg)
    verifyKey = RSA.import_key(other_pub_key)
    verifier = PKCS1_v1_5.new(verifyKey)
    if not verifier.verify(digest, signature):
        print('message has been modified!')
        sys.exit()
    return msg.decode('utf-8')


def send_nonce(conn, private_key, client_pub_key, nonce):

    clientPublicKey = RSA.import_key(client_pub_key)
    cipher = PKCS1_OAEP.new(clientPublicKey)

    privateKey = RSA.import_key(private_key)
    signer = PKCS1_v1_5.new(privateKey)

    encrypted_key = cipher.encrypt(nonce)
    conn.send(encrypted_key)

    digest = SHA256.new()
    digest.update(nonce)
    signature = signer.sign(digest)
    conn.send(signature)


def receive_nonce(s, private_key, server_pub_key):
    AES_crypto_nonce = s.recv(128)

    privateKey = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(privateKey)
    AES_crypto_nonce = cipher.decrypt(AES_crypto_nonce)

    digest = SHA256.new()
    digest.update(AES_crypto_nonce)

    signature = s.recv(128)

    publicKey = RSA.import_key(server_pub_key)
    signer = PKCS1_v1_5.new(publicKey)
    if not signer.verify(digest, signature):
        print('server public key has been modified!')
        sys.exit()
    return AES_crypto_nonce
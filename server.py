'''
Author: Leon-Francis
Date: 2021-07-07 22:13:38
Contact: leon_francis@163.com
LastEditTime: 2021-07-09 00:41:34
LastEditors: Leon-Francis
Description: socket_server
FilePath: /Network_Security_Experiment/server.py
(C)Copyright 2020-2021, Leon-Francis
'''
import socket
import os
from crypto import get_RSA_keys, get_random_bytes, crypto_encode, crypto_decode, get_msg_len, receive_nonce, send_nonce
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import sys

HOST = socket.gethostname()
PORT = 11223
MSG_HEADER_LEN = 10

with socket.socket() as s:
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        with open('AES_key', 'rb') as f:
            AES_key = f.read()

        private_key, public_key = get_RSA_keys()
        client_pub_key = conn.recv(271)

        conn.send(public_key)

        while True:
            command = conn.recv(1)
            if command == b'\04':
                break
            if command == b'\31':
                nonce = receive_nonce(conn, private_key, client_pub_key)
                message_header = conn.recv(MSG_HEADER_LEN)
                message_len = int(message_header.decode('utf-8'))
                message = conn.recv(message_len)
                message = crypto_decode(message, private_key, client_pub_key,
                                        nonce)
                print('Get message from client:')
                print(message)
            if command == b'\32':
                nonce = receive_nonce(conn, private_key, client_pub_key)
                file_name_header = conn.recv(MSG_HEADER_LEN)
                file_name_len = int(file_name_header.decode('utf-8'))
                file_name = conn.recv(file_name_len)
                file_name = crypto_decode(file_name, private_key,
                                          client_pub_key, nonce)
                file_path = 'file_1/' + file_name
                with open(file_path, 'w') as f:
                    while True:
                        more_line = conn.recv(1)
                        if more_line == b'\03':
                            break
                        nonce = receive_nonce(conn, private_key,
                                              client_pub_key)
                        line_header = conn.recv(MSG_HEADER_LEN)
                        line_len = int(line_header.decode('utf-8'))
                        line = conn.recv(line_len)
                        line = crypto_decode(line, private_key, client_pub_key,
                                             nonce)
                        f.writelines(line)
                print(f'received file {file_name}')
            if command == b'\33':
                for file_name in os.listdir('file_1'):
                    conn.send(b'\02')
                    file_name, nonce = crypto_encode(file_name, private_key, client_pub_key)
                    send_nonce(conn, private_key, client_pub_key, nonce)
                    conn.send(get_msg_len(file_name).encode('utf-8'))
                    conn.send(file_name)
                conn.send(b'\03')
                download_file = conn.recv(1)
                if download_file != b'\03':
                    nonce = receive_nonce(conn, private_key, client_pub_key)
                    file_name_header = conn.recv(MSG_HEADER_LEN)
                    file_name_len = int(file_name_header.decode('utf-8'))
                    file_name = conn.recv(file_name_len)
                    file_name = crypto_decode(file_name, private_key,
                                              client_pub_key, nonce)
                    file_path = 'file_1/' + file_name
                    with open(file_path, 'r') as f:
                        for line in f:
                            conn.send(b'\02')
                            line, nonce = crypto_encode(
                                line, private_key, client_pub_key)
                            send_nonce(conn, private_key, client_pub_key, nonce)
                            conn.send(get_msg_len(line).encode('utf-8'))
                            conn.send(line)
                    conn.send(b'\03')
                    print(f'download {file_name} by {addr}')

print('Disconnect by client')
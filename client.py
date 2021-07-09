'''
Author: Leon-Francis
Date: 2021-07-07 22:13:56
Contact: leon_francis@163.com
LastEditTime: 2021-07-09 00:46:49
LastEditors: Leon-Francis
Description: socket_server
FilePath: /Network_Security_Experiment/client.py
(C)Copyright 2020-2021, Leon-Francis
'''
import socket
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
    s.connect((HOST, PORT))
    print(f'Connected to {HOST}:{PORT}')

    private_key, public_key = get_RSA_keys()
    s.send(public_key)

    server_pub_key = s.recv(271)

    while True:
        print('1, send message')
        print('2, upload file')
        print('3, download file')
        print('4, close the connect')
        command = input('Plz input the number 1-4: ')
        if command == '4':
            s.send(b'\04')
            break
        if command == '1':
            message = input('Plz input the massage: ')
            s.send(b'\31')
            message, nonce = crypto_encode(message, private_key,
                                           server_pub_key)
            send_nonce(s, private_key, server_pub_key, nonce)
            s.send(get_msg_len(message).encode('utf-8'))
            s.send(message)
        if command == '2':
            file_name = input('Plz input the file name: ')
            file_path = 'file_2/' + file_name
            s.send(b'\32')
            file_name, nonce = crypto_encode(file_name, private_key,
                                             server_pub_key)
            send_nonce(s, private_key, server_pub_key, nonce)
            s.send(get_msg_len(file_name).encode('utf-8'))
            s.send(file_name)
            with open(file_path, 'r') as f:
                for line in f:
                    s.send(b'\02')
                    line, nonce = crypto_encode(line, private_key,
                                                server_pub_key)
                    send_nonce(s, private_key, server_pub_key, nonce)
                    s.send(get_msg_len(line).encode('utf-8'))
                    s.send(line)
            s.send(b'\03')
        if command == '3':
            s.send(b'\33')
            print('The file in server is as follows:')
            while True:
                more_file_name = s.recv(1)
                if more_file_name == b'\03':
                    break
                nonce = receive_nonce(s, private_key, server_pub_key)
                file_name_header = s.recv(MSG_HEADER_LEN)
                file_name_len = int(file_name_header.decode('utf-8'))
                file_name = s.recv(file_name_len)
                file_name = crypto_decode(file_name, private_key,
                                          server_pub_key, nonce)
                print(file_name)
            download_file_name = input(
                'Which one you want to download?(-1 to quit) ')
            if download_file_name == '-1':
                s.send(b'\03')
            else:
                s.send(b'\02')
                old_file_name = download_file_name
                file_path = 'file_2/' + download_file_name
                download_file_name, nonce = crypto_encode(
                    download_file_name, private_key, server_pub_key)
                send_nonce(s, private_key, server_pub_key, nonce)
                s.send(get_msg_len(download_file_name).encode('utf-8'))
                s.send(download_file_name)
                with open(file_path, 'w') as f:
                    while True:
                        more_line = s.recv(1)
                        if more_line == b'\03':
                            break
                        nonce = receive_nonce(s, private_key, server_pub_key)
                        line_header = s.recv(MSG_HEADER_LEN)
                        line_len = int(line_header.decode('utf-8'))
                        line = s.recv(line_len)
                        line = crypto_decode(line, private_key, server_pub_key,
                                             nonce)
                        f.writelines(line)
                print(f'download {old_file_name} from {HOST}')

print('Disconnect')
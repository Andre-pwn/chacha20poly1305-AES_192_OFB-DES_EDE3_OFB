# ECB should not be used if encrypting more than one block of data with the same key.

# CBC, OFB and CFB are similar, however OFB/CFB is better because you only need encryption and not decryption,
# which can save code space.

# CTR is used if you want good parallelization (ie. speed), instead of CBC/OFB/CFB.

# XTS mode is the most common if you are encoding a random accessible data (like a hard disk or RAM).

# OCB is by far the best mode, as it allows encryption and authentication in a single pass.

import time
import os
from chacha20poly1305 import ChaCha20Poly1305
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import DES3


def chacha20poly1305_cifra_decifra(filepath, dim):
    f = open(filepath, "rb")
    # cifra chacha20poly1305
    start_time = time.time()
    key = os.urandom(32)
    cip = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    bytestream = f.read()
    ciphertext = cip.encrypt(nonce, bytestream)
    print("--- %s seconds seconds taken for encoding the %s kb file with chacha20poly1305 ---" % (
    (time.time() - start_time), dim))
    start_time = time.time()
    plaintext = cip.decrypt(nonce, ciphertext)
    print("--- %s seconds taken for decoding the %s kb file with chacha20poly1305 ---" % (
    (time.time() - start_time), dim))

    if bytestream == plaintext:
        print("Decoded cyphertext and original plaintext are the same, it works!")
    else:
        print("Decoded cyphertext and original plaintext are different ,some errors occurred!")
    f.close()


def aes_192_ofb_cifra_decifra(filepath, dim):
    f = open(filepath, "rb")
    start_time = time.time()
    key = os.urandom(24)  # for 192
    cipher = AES.new(key, AES.MODE_OFB)
    iv = cipher.iv
    bytestream = f.read()
    ciphertext = cipher.encrypt(bytestream)
    print("--- %s seconds seconds taken for encoding the %s kb file with aes_192_ofb ---" % (
    (time.time() - start_time), dim))
    start_time = time.time()
    cipher = AES.new(key, AES.MODE_OFB, iv)
    plaintext = cipher.decrypt(ciphertext)
    print("--- %s seconds taken for decoding the %s kb file with aes_192_ofb ---" % ((time.time() - start_time), dim))

    if bytestream == plaintext:
        print("Decoded cyphertext and original plaintext are the same, it works!")
    else:
        print("Decoded cyphertext and original plaintext are different ,some errors occurred!")
    f.close()


def des_ede3_ofb(filepath, dim):
    f = open(filepath, "rb")
    start_time = time.time()
    key = os.urandom(16)  # for 128
    iv = os.urandom(8)
    cipher = DES3.new(key, DES3.MODE_OFB, iv)
    bytestream = f.read()
    ciphertext = cipher.encrypt(bytestream)
    print("--- %s seconds seconds taken for encoding the %s kb file with aes_192_ofb ---" % (
    (time.time() - start_time), dim))
    start_time = time.time()
    cipher = DES3.new(key, DES3.MODE_OFB, iv)
    plaintext = cipher.decrypt(ciphertext)
    print("--- %s seconds taken for decoding the %s kb file with aes_192_ofb ---" % ((time.time() - start_time), dim))

    if bytestream == plaintext:
        print("Decoded cyphertext and original plaintext are the same, it works!")
    else:
        print("Decoded cyphertext and original plaintext are different ,some errors occurred!")
    f.close()


def __main__():
    chacha20poly1305_cifra_decifra("C:/Users/Win10/Desktop/100kb.zip",100)
    chacha20poly1305_cifra_decifra("C:/Users/Win10/Desktop/500kb.zip",500)
    chacha20poly1305_cifra_decifra("C:/Users/Win10/Desktop/1000kb.zip",1000)
    chacha20poly1305_cifra_decifra("C:/Users/Win10/Desktop/1500kb.zip",1500)
    aes_192_ofb_cifra_decifra("C:/Users/Win10/Desktop/100kb.zip",100)
    aes_192_ofb_cifra_decifra("C:/Users/Win10/Desktop/500kb.zip",500)
    aes_192_ofb_cifra_decifra("C:/Users/Win10/Desktop/1000kb.zip",1000)
    aes_192_ofb_cifra_decifra("C:/Users/Win10/Desktop/1500kb.zip",1500)
    des_ede3_ofb("C:/Users/Win10/Desktop/100kb.zip", 100)
    des_ede3_ofb("C:/Users/Win10/Desktop/500kb.zip", 500)
    des_ede3_ofb("C:/Users/Win10/Desktop/1000kb.zip", 1000)
    des_ede3_ofb("C:/Users/Win10/Desktop/1500kb.zip", 1500)


__main__()

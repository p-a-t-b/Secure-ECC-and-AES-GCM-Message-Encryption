from Crypto.Cipher import AES
import hashlib
import binascii
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return ciphertext, aesCipher.nonce, authTag

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    try:
        aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
        plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
        return plaintext
    except ValueError as e:
        raise ValueError("Decryption failed. Error: {}".format(e))

def ecc_point_to_256_bit_key(pubKey):
    sha = hashlib.sha256(pubKey)
    return sha.digest()

def load_friend_public_key(file_path):
    with open(file_path, "rb") as key_file:
        friend_public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return friend_public_key

def decrypt_ECC(privKey, encryptedMsg, friend_public_key):
    curve = ec.SECP256R1()
    private_key = serialization.load_pem_private_key(privKey, password=None, backend=default_backend())
    sharedECCKey = private_key.exchange(ec.ECDH(), friend_public_key)
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(encryptedMsg[0], encryptedMsg[1], encryptedMsg[2], secretKey)
    return plaintext

def main():
    choice = input("Do you want to encrypt (e) or decrypt (d) a message? Enter 'e' or 'd': ")

    if choice.lower() == 'e':
        msg = input("Enter the message to be encrypted: ").encode()

        curve = ec.SECP256R1()
        private_key = ec.generate_private_key(curve, backend=default_backend())
        public_key = private_key.public_key()

        friend_public_key_file = input("Enter the file path to your friend's public key: ")
        friend_public_key = load_friend_public_key(friend_public_key_file)

        ciphertext, nonce, authTag = encrypt_AES_GCM(msg, ecc_point_to_256_bit_key(private_key.exchange(ec.ECDH(), friend_public_key)))
        encryptedMsg = {
            'ciphertext': binascii.hexlify(ciphertext),
            'nonce': binascii.hexlify(nonce),
            'authTag': binascii.hexlify(authTag)
        }

        print("Encrypted message:", encryptedMsg)

    elif choice.lower() == 'd':
        private_key_file = input("Enter the file path to your private key: ")
        friend_public_key_file = input("Enter the file path to your friend's public key: ")
        encryptedText = input("Enter the encrypted text: ")
        nonce = input("Enter the nonce: ")
        authTag = input("Enter the authentication tag: ")

        with open(private_key_file, "rb") as key_file:
            private_key = key_file.read()

        friend_public_key = load_friend_public_key(friend_public_key_file)

        ciphertext = binascii.unhexlify(encryptedText)
        nonce = binascii.unhexlify(nonce)
        authTag = binascii.unhexlify(authTag)

        encryptedMsg = (ciphertext, nonce, authTag)

        try:
            decryptedMsg = decrypt_ECC(private_key, encryptedMsg, friend_public_key)
            print("Decrypted message:", decryptedMsg.decode())
        except ValueError as e:
            print("Decryption failed. Error: {}".format(e))

if __name__ == "__main__":
    main()

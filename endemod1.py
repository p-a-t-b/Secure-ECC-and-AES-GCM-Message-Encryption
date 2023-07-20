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
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext


def ecc_point_to_256_bit_key(pubKey):
    sha = hashlib.sha256(pubKey)
    return sha.digest()


def serialize_pub_key(pubKey):
    return pubKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_pub_key(serialized_pub_key):
    return serialization.load_pem_public_key(serialized_pub_key, backend=default_backend())


def encrypt_ECC(pubKey):
    # Get message from user
    msg = input("Enter the message to be encrypted: ").encode()

    curve = ec.SECP256R1()
    privateKey = ec.generate_private_key(curve, default_backend())
    pubKeyObj = deserialize_pub_key(pubKey)
    sharedECCKey = privateKey.exchange(ec.ECDH(), pubKeyObj)
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = serialize_pub_key(privateKey.public_key())
    return ciphertext, nonce, authTag, ciphertextPubKey


def decrypt_ECC(privKey, encryptedMsg):
    curve = ec.SECP256R1()
    privateKey = serialization.load_pem_private_key(privKey, password=None, backend=default_backend())
    pubKeyObj = deserialize_pub_key(encryptedMsg[3])
    sharedECCKey = privateKey.exchange(ec.ECDH(), pubKeyObj)
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(encryptedMsg[0], encryptedMsg[1], encryptedMsg[2], secretKey)
    return plaintext


def print_options():
    print("Select an option:")
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    print("3. Exit")


def save_to_file(file_path, data):
    with open(file_path, "wb") as file:
        file.write(data)


def main():
    # Generate ECC key pair
    curve = ec.SECP256R1()
    privateKey = ec.generate_private_key(curve, default_backend())
    pubKey = serialize_pub_key(privateKey.public_key())
    privKey = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    while True:
        print_options()
        choice = input("Enter your choice (1, 2, or 3): ")

        if choice == '1':
            # Encryption
            print("\n=== Encryption ===")
            encryptedMsg = encrypt_ECC(pubKey)
            encryptedMsgObj = {
                'ciphertext': binascii.hexlify(encryptedMsg[0]),
                'nonce': binascii.hexlify(encryptedMsg[1]),
                'authTag': binascii.hexlify(encryptedMsg[2]),
                'ciphertextPubKey': binascii.hexlify(encryptedMsg[3])
            }
            save_to_file("encrypted_message.txt", str(encryptedMsgObj).encode())
            print("Encrypted message saved to 'encrypted_message.txt'")
        elif choice == '2':
            # Decryption
            print("\n=== Decryption ===")
            encryptedText = input("Enter the encrypted text: ")
            ciphertext = binascii.unhexlify(encryptedText)
            nonce = binascii.unhexlify(input("Enter the nonce: "))
            authTag = binascii.unhexlify(input("Enter the authentication tag: "))
            pubKey = binascii.unhexlify(input("Enter the public key: "))

            decryptedMsg = decrypt_ECC(privKey, (ciphertext, nonce, authTag, pubKey))
            save_to_file("decrypted_message.txt", decryptedMsg)
            print("Decrypted message saved to 'decrypted_message.txt'")
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()

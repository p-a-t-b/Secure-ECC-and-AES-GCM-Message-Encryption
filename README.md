# Secure-ECC-and-AES-GCM-Message-Encryption
This Python script showcases secure message encryption and decryption using Elliptic Curve Cryptography (ECC) for key exchange and AES-GCM for symmetric encryption. Encrypt messages for friends and decrypt received messages with ease. Save encrypted and decrypted messages in separate files for convenience.
# Secure ECC and AES-GCM Message Encryption

This Python script demonstrates a secure message encryption and decryption system using Elliptic Curve Cryptography (ECC) for key exchange and AES-GCM for symmetric encryption. The program allows users to encrypt messages for their friends using their public key and decrypt received messages using their private key. The encrypted and decrypted messages can be saved in separate files for easy access.

# Features:
- Encrypt messages for friends using their public key
- Decrypt received messages using your private key
- Save encrypted and decrypted messages in separate files
- Elliptic Curve Cryptography (ECC) for secure key exchange
- AES-GCM for symmetric encryption with authenticated encryption
- User-friendly command-line interface

# Requirements:
- Python 3.x
- Crypto.Cipher library
- cryptography library

# Usage:
1. Run the script and choose an option (1 for encryption, 2 for decryption, 3 to exit).
2. For encryption, enter your friend's public key file (in PEM format) and the message to be encrypted.
3. For decryption, enter the path to your private key file (in PEM format), and the required encryption details.

# Note:
Please ensure you have the necessary permissions and the correct key files for encryption and decryption.

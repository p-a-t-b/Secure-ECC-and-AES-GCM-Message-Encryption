from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_ecc_key_pair():
    curve = ec.SECP256R1()
    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()


    return private_key, public_key

def save_private_key_to_file(private_key, file_path):
    with open(file_path, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # No encryption for private key
        ))

def save_public_key_to_file(public_key, file_path):
    with open(file_path, "wb") as key_file:
        key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

if __name__ == "__main__":
    private_key, public_key = generate_ecc_key_pair()

    private_key_file_path = "private_key.pem"
    public_key_file_path = "public_key.pem"

    save_private_key_to_file(private_key, private_key_file_path)
    save_public_key_to_file(public_key, public_key_file_path)

    print("Private key saved to:", private_key_file_path)
    print("Public key saved to:", public_key_file_path)

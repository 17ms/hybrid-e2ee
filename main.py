from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import secrets
import sys

# Hybrid encryption (RSA + AES256-GCM)

if len(sys.argv) != 2:
    print(f"Incorrect arguments ({len(sys.argv)})")
    sys.exit(1)
else:
    data = str.encode(sys.argv[1])

symmetric_key_sender = AESGCM.generate_key(256)
aes_sender = AESGCM(symmetric_key_sender)
nonce_sender = secrets.token_bytes(12)

private_key = rsa.generate_private_key(65537, 4096)
public_key = private_key.public_key()

# Encryption
enc_symmetric_key = public_key.encrypt(symmetric_key_sender, padding.OAEP(padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
enc_data = aes_sender.encrypt(nonce_sender, data, b"")
packet = {"key": enc_symmetric_key, "nonce": nonce_sender, "data": enc_data}

# Decryption
symmetric_key_receiver = private_key.decrypt(packet["key"], padding.OAEP(padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
aes_receiver = AESGCM(symmetric_key_receiver)
nonce_receiver = packet["nonce"]
dec_data = aes_receiver.decrypt(nonce_receiver, packet["data"], b"")

assert dec_data == data
print(f"Sent: {data}\nReceived: {dec_data}")

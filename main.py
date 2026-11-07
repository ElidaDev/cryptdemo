
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

message = "test message"
data = message.encode("utf-8")
lines = []


def log(text=""):
    print(text)
    lines.append(text)


log(f"INPUT (plaintext): {message}")
log()

sym_key = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)  # must be unique per message
aes = AESGCM(sym_key)
sym_cipher = aes.encrypt(nonce, data, None)
sym_plain = aes.decrypt(nonce, sym_cipher, None).decode("utf-8")

log("SYMMETRIC (AES-256-GCM)")
log(f"Key (shared secret, hex): {sym_key.hex()}")
log(f"Nonce (hex):              {nonce.hex()}")
log(f"Ciphertext (hex):         {sym_cipher.hex()}")
log(f"Decrypted output:         {sym_plain}")
log(f"Match original:           {sym_plain == message}")
log()

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
oaep = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)
asym_cipher = public_key.encrypt(data, oaep)  # encrypt with PUBLIC key
asym_plain = private_key.decrypt(asym_cipher, oaep).decode("utf-8")  # decrypt with PRIVATE key

pub_pem = public_key.public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
).decode()
priv_pem = private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()

log("ASYMMETRIC (RSA-2048, OAEP/SHA-256)")
log("Public key (used to encrypt):")
log(pub_pem.strip())
log()
log("Private key (used to decrypt)")
log(priv_pem.strip())
log()
log(f"Ciphertext (hex): {asym_cipher.hex()}")
log(f"Decrypted output: {asym_plain}")
log(f"Match original:   {asym_plain == message}")

with open("output.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")

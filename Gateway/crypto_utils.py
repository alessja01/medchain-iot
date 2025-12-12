import os  # genera numeri casuali sicuri
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # AES-GCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def encrypt_key_for_doctor(data_key: bytes, pubkey_path: str) -> bytes:
    """Cifra la chiave AES (data_key) con la chiave pubblica del medico (RSA-OAEP)."""
    with open(pubkey_path, "rb") as f:
        pubkey = serialization.load_pem_public_key(f.read())

    enc_key = pubkey.encrypt(
        data_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return enc_key


def encrypt_aes_gcm_256(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Cifra plaintext con AES-256-GCM usando 'key'.
    Ritorna: (nonce, ciphertext, tag).
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96 bit, standard per GCM

    ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return nonce, ciphertext, tag


def hash_sha256(data: bytes) -> str:
    """Restituisce l'hash SHA-256 in esadecimale."""
    return sha256(data).hexdigest()

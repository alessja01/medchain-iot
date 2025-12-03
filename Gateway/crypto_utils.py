import os #genera numeri casuali sicuri
from hashlib import sha256 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


#definisco funzione che input testo in chiaro come sequenza di bytes--> restituisce tupla chiave, valore random usato da GCM, dati cifrati 
def encrypt_aes_gcm_256(plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    
    key=AESGCM.generate_key(bit_length=256) # genera una chiave casuale 
    aesgcm= AESGCM(key)#crea un oggetto cifratore 
    nonce=os.urandom(12) # genera numeri casuali
    ciphertext= aesgcm.encrypt(nonce, plaintext, None) #restituisce dati cifrati + tag di autenticazione
    return key, nonce, ciphertext


def hash_sha256(data:bytes) -> str:
    #restituisce l'hash in formato stringa esadecimale
    return sha256(data).hexdigest()

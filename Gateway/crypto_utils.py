import os #genera numeri casuali sicuri
from hashlib import sha256 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


#definisco funzione che input testo in chiaro come sequenza di bytes--> restituisce tupla chiave, valore random usato da GCM, dati cifrati 
def encrypt_aes_gcm_256(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    
    aesgcm= AESGCM(key)#crea un oggetto cifratore 
    nonce=os.urandom(12) # genera numeri casuali
    
    ct_with_tag=aesgcm.encrypt(nonce, plaintext, None)

    ciphertext=ct_with_tag[:-16]
    tag=ct_with_tag[-16:] 
    return nonce, ciphertext, tag



def hash_sha256(data:bytes) -> str:
    #restituisce l'hash in formato stringa esadecimale
    return sha256(data).hexdigest()

from Crypto.PublicKey import RSA

key = RSA.generate(2048)
private_key = key.export_key()
with open("doctor_private.pem", "wb") as f:
    f.write(private_key)

public_key = key.publickey().export_key()
with open("doctor_public.pem", "wb") as f:
    f.write(public_key)

print("Coppia di chiavi rigenerata con successo! ")
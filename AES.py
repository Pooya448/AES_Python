import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

key = "Security"

block_size = AES.block_size
AES_key = hashlib.sha256(key.encode()).digest()


def pad(plain_text):
    nbytes_to_pad = block_size - len(plain_text) % block_size
    ascii = chr(nbytes_to_pad)
    padding = nbytes_to_pad * ascii
    final_padding = plain_text + padding
    return final_padding

def unpad(plain_text):
    l = len(plain_text) - 1
    last = plain_text[l:]
    bytes_to_remove = ord(last)
    return plain_text[:-bytes_to_remove]

def encrypt(plain_text):
    paded = pad(plain_text)
    rn = Random.new().read(block_size)
    cipher = AES.new(AES_key, AES.MODE_CBC, rn)
    encrypted_text = cipher.encrypt(paded.encode())
    return b64encode(rn + encrypted_text).decode("utf-8")

def decrypt(encrypted_text):
    encrypted_text_decoded = b64decode(encrypted_text)
    rn = encrypted_text_decoded[:block_size]
    cipher = AES.new(AES_key, AES.MODE_CBC, rn)
    plain_text_padded = cipher.decrypt(encrypted_text_decoded[block_size:]).decode("utf-8")
    return unpad(plain_text_padded)

print(f"Encyption Key: {key}")

plain_text = "ThIs Is A tEsT sTRiNg"
print(f"Plain Text: {plain_text}")

coded = encrypt(plain_text)
print(f"Encrypted Text: {coded}")

decoded = decrypt(coded)
print(f"Decrypted Text: {decoded}")

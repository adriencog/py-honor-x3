import base64
from binascii import hexlify
import hashlib
import hmac
import math
import uuid

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey.RSA import construct

"""
SCRAM challenge from https://github.com/jinxo13/HuaweiB525Router
"""


def generate_nonce():
    """Generate random clientside nonce."""
    return uuid.uuid4().hex + uuid.uuid4().hex


def get_client_proof(clientnonce, servernonce, password, salt, iterations):
    """Calculates server client proof (part of the SCRAM algorithm)."""
    msg = "%s,%s,%s" % (clientnonce, servernonce, servernonce)
    salted_pass = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf_8"), bytearray.fromhex(salt), iterations
    )
    client_key = hmac.new(b"Client Key", msg=salted_pass, digestmod=hashlib.sha256)
    stored_key = hashlib.sha256()
    stored_key.update(client_key.digest())
    signature = hmac.new(
        msg.encode("utf_8"), msg=stored_key.digest(), digestmod=hashlib.sha256
    )
    client_key_digest = client_key.digest()
    signature_digest = signature.digest()
    client_proof = bytearray()
    i = 0
    while i < client_key.digest_size:
        client_proof.append(client_key_digest[i] ^ signature_digest[i])
        i = i + 1
    return hexlify(client_proof)


def rsa_encrypt(rsae, rsan, data):  # noqa: D103
    if data is None or data == "":
        return ""
    N = int(rsan, 16)
    E = int(rsae, 16)
    b64data = base64.b64encode(data)
    pubkey = construct((N, E))
    cipher = PKCS1_v1_5.new(pubkey)
    blocks = int(math.ceil(len(b64data) / 245.0))
    result = []
    for i in range(blocks):
        block = b64data[i * 245 : (i + 1) * 245]
        d = cipher.encrypt(block)
        result.append(d)
    result = hexlify("".join(result))
    if (len(result) & 1) == 0:
        return result
    return "0" + result

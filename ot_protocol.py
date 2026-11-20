import secrets
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# RFC 3526, 2048-bit MODP group (Group 14)
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF05 98DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
    .replace(" ", ""),
    16
)

Q = (P - 1) // 2
G = 2
KEY_SIZE = 256


def generate_exponent():
    return secrets.randbelow(Q - 3) + 2


def derive_key(shared_secret, label):
    secret_bytes = shared_secret.to_bytes(KEY_SIZE, "big")
    return hashlib.sha256(
        secret_bytes + label
    ).digest()


def create_sender_offer():
    """
    Sender generates a private exponent and public DH value.
    """
    a = generate_exponent()
    C = pow(G, a, P)

    return a, C


def create_receiver_request(C, choice):
    """
    Receiver creates a public response based on its choice bit.

    choice = 0: PK0 = G^k
    choice = 1: PK0 = C / G^k
    """
    if choice not in (0, 1):
        raise ValueError("Choice must be 0 or 1")

    k = generate_exponent()
    R = pow(G, k, P)

    if choice == 0:
        PK0 = R
    else:
        PK0 = (C * pow(R, -1, P)) % P

    return k, PK0


def encrypt_messages(a, C, PK0, message0, message1):
    """
    Sender derives two keys and encrypts both messages.

    The sender receives PK0, not the receiver's choice bit.
    """
    if not (1 < PK0 < P - 1):
        raise ValueError("Invalid receiver public value")

    if pow(PK0, Q, P) != 1:
        raise ValueError("Receiver public value is not in the expected subgroup")

    PK1 = (C * pow(PK0, -1, P)) % P

    shared0 = pow(PK0, a, P)
    shared1 = pow(PK1, a, P)

    key0 = derive_key(shared0, b"SecureOT-message-0")
    key1 = derive_key(shared1, b"SecureOT-message-1")

    nonce0 = secrets.token_bytes(12)
    nonce1 = secrets.token_bytes(12)

    ciphertext0 = AESGCM(key0).encrypt(
        nonce0, message0.encode("utf-8"), b"OT-M0"
    )

    ciphertext1 = AESGCM(key1).encrypt(
        nonce1, message1.encode("utf-8"), b"OT-M1"
    )

    return {
        "nonce0": nonce0,
        "nonce1": nonce1,
        "ciphertext0": ciphertext0,
        "ciphertext1": ciphertext1
    }


def decrypt_selected_message(k, C, choice, encrypted_data):
    """
    Receiver derives the shared key and decrypts only its selected message.
    """
    shared_secret = pow(C, k, P)

    if choice == 0:
        key = derive_key(shared_secret, b"SecureOT-message-0")

        plaintext = AESGCM(key).decrypt(
            encrypted_data["nonce0"],
            encrypted_data["ciphertext0"],
            b"OT-M0"
        )

    elif choice == 1:
        key = derive_key(shared_secret, b"SecureOT-message-1")

        plaintext = AESGCM(key).decrypt(
            encrypted_data["nonce1"],
            encrypted_data["ciphertext1"],
            b"OT-M1"
        )

    else:
        raise ValueError("Choice must be 0 or 1")

    return plaintext.decode("utf-8")
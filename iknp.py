import secrets
import hashlib
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ot_protocol import (
    create_sender_offer,
    create_receiver_request,
    encrypt_messages,
    decrypt_selected_message
)


SECURITY_PARAMETER = 128


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def expand_seed(seed, length):
    """Expand a random seed into a pseudorandom bit string."""
    byte_length = (length + 7) // 8
    return hashlib.shake_256(seed).digest(byte_length)


def pack_bits(bits):
    """Pack a list of bits into bytes, least-significant bit first."""
    packed = bytearray((len(bits) + 7) // 8)

    for j, bit in enumerate(bits):
        if bit:
            packed[j // 8] |= 1 << (j % 8)

    return bytes(packed)


def get_bit(data, index):
    return (data[index // 8] >> (index % 8)) & 1


def extract_column(rows, column_index):
    """Extract one column from the matrix of packed rows."""
    column = bytearray((len(rows) + 7) // 8)

    for row_index, row in enumerate(rows):
        if get_bit(row, column_index):
            column[row_index // 8] |= 1 << (row_index % 8)

    return bytes(column)


def derive_iknp_key(column, index):
    """Derive an AES key from an IKNP column."""
    return hashlib.sha256(
        b"SecureOT-IKNP-v1" +
        index.to_bytes(4, "big") +
        column
    ).digest()


def perform_base_ots():
    """
    Perform 128 DH-based base OTs.

    Extended receiver acts as base-OT sender.
    Extended sender acts as base-OT receiver.
    """

    receiver_seed_pairs = []
    sender_selected_seeds = []
    sender_choices = []

    for _ in range(SECURITY_PARAMETER):

        seed0 = secrets.token_bytes(32)
        seed1 = secrets.token_bytes(32)

        choice = secrets.randbits(1)

        private_key, public_key = create_sender_offer()

        receiver_private, receiver_public = create_receiver_request(
            public_key, choice
        )

        encrypted = encrypt_messages(
            private_key,
            public_key,
            receiver_public,
            seed0.hex(),
            seed1.hex()
        )

        selected_seed = bytes.fromhex(
            decrypt_selected_message(
                receiver_private,
                public_key,
                choice,
                encrypted
            )
        )

        receiver_seed_pairs.append((seed0, seed1))
        sender_selected_seeds.append(selected_seed)
        sender_choices.append(choice)

    return receiver_seed_pairs, sender_selected_seeds, sender_choices


def iknp_ot_extension(message_pairs, receiver_choices):
    """
    Educational semi-honest IKNP OT extension.

    Returns only the messages selected by the receiver.
    """

    if not message_pairs:
        raise ValueError("At least one message pair is required.")

    if len(message_pairs) != len(receiver_choices):
        raise ValueError("Each message pair needs one choice bit.")

    if any(bit not in (0, 1) for bit in receiver_choices):
        raise ValueError("Choices must contain only 0 or 1.")

    total_start = time.perf_counter()

    n = len(message_pairs)
    k = SECURITY_PARAMETER

    # Phase 1: Perform Base OTs.
    base_ot_start = time.perf_counter()

    receiver_seed_pairs, sender_seeds, s_bits = perform_base_ots()

    base_ot_time = (
        time.perf_counter() - base_ot_start
    ) * 1000

    # Start measuring the extension separately.
    extension_start = time.perf_counter()

    # Phase 2: Extended receiver creates T and U matrices.
    r = pack_bits(receiver_choices)

    t_rows = []
    u_rows = []

    for i in range(k):

        seed0, seed1 = receiver_seed_pairs[i]

        t0 = expand_seed(seed0, n)
        t1 = expand_seed(seed1, n)

        u = xor_bytes(xor_bytes(t0, t1), r)

        t_rows.append(t0)
        u_rows.append(u)

    # Phase 3: Extended sender constructs Q matrix.
    q_rows = []

    for i in range(k):

        q = expand_seed(sender_seeds[i], n)

        if s_bits[i] == 1:
            q = xor_bytes(q, u_rows[i])

        q_rows.append(q)

    # Pack the sender's secret base-OT choice vector.
    s_vector = pack_bits(s_bits)

    # Phase 4: Generate keys and encrypt message pairs.
    encrypted_messages = []

    for j, (message0, message1) in enumerate(message_pairs):

        q_column = extract_column(q_rows, j)

        key0 = derive_iknp_key(q_column, j)

        key1 = derive_iknp_key(
            xor_bytes(q_column, s_vector), j
        )

        nonce0 = secrets.token_bytes(12)
        nonce1 = secrets.token_bytes(12)

        aad0 = b"IKNP-M0-" + j.to_bytes(4, "big")
        aad1 = b"IKNP-M1-" + j.to_bytes(4, "big")

        ciphertext0 = AESGCM(key0).encrypt(
            nonce0, message0.encode("utf-8"), aad0
        )

        ciphertext1 = AESGCM(key1).encrypt(
            nonce1, message1.encode("utf-8"), aad1
        )

        encrypted_messages.append({
            "nonce0": nonce0,
            "nonce1": nonce1,
            "ciphertext0": ciphertext0,
            "ciphertext1": ciphertext1
        })

    # Phase 5: Extended receiver derives selected keys and decrypts.
    received_messages = []

    for j, choice in enumerate(receiver_choices):

        t_column = extract_column(t_rows, j)

        key = derive_iknp_key(t_column, j)

        encrypted = encrypted_messages[j]

        if choice == 0:
            plaintext = AESGCM(key).decrypt(
                encrypted["nonce0"],
                encrypted["ciphertext0"],
                b"IKNP-M0-" + j.to_bytes(4, "big")
            )

        else:
            plaintext = AESGCM(key).decrypt(
                encrypted["nonce1"],
                encrypted["ciphertext1"],
                b"IKNP-M1-" + j.to_bytes(4, "big")
            )

        received_messages.append(plaintext.decode("utf-8"))

    extension_time = (
        time.perf_counter() - extension_start
    ) * 1000

    total_time = (
        time.perf_counter() - total_start
    ) * 1000

    return {
        "received_messages": received_messages,
        "number_of_transfers": n,
        "base_ots": k,
        "base_ot_time_ms": round(base_ot_time, 3),
        "extension_time_ms": round(extension_time, 3),
        "execution_time_ms": round(total_time, 3)
    }
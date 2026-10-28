
import secrets
from py_ecc.bls import G2ProofOfPossession as BLS


def keygen():
    """Generate a BLS key pair and proof of possession."""
    ikm = secrets.token_bytes(32)
    sk = BLS.KeyGen(ikm)
    pk = BLS.SkToPk(sk)
    pop = BLS.PopProve(sk)
    return sk, pk, pop


def sign(sk, message):
    """Sign a byte message with a BLS private key."""
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    return BLS.Sign(sk, message)


def aggregate(signatures):
    """Combine multiple BLS signatures into one."""
    if not signatures:
        raise ValueError("At least one signature is required")
    return BLS.Aggregate(signatures)


def verify_aggregate(public_keys, messages, agg_signature, proofs):
    """
    Verify an aggregate signature over potentially different messages.
    Every public key must have a valid proof of possession.
    """
    if not public_keys or len(public_keys) != len(messages):
        return False

    if len(public_keys) != len(proofs):
        return False

    try:
        for pk, pop in zip(public_keys, proofs):
            if not BLS.KeyValidate(pk):
                return False
            if not BLS.PopVerify(pk, pop):
                return False

        return BLS.AggregateVerify(
            public_keys, messages, agg_signature
        )
    except (ValueError, TypeError, AssertionError):
        return False


if __name__ == "__main__":
    # Simulate 10 IoT sensors
    sensors = [keygen() for _ in range(10)]

    private_keys = [sensor[0] for sensor in sensors]
    public_keys = [sensor[1] for sensor in sensors]
    proofs = [sensor[2] for sensor in sensors]

    messages = [
        f"sensor-{i}:temperature={20 + i}".encode("utf-8")
        for i in range(10)
    ]

    signatures = [
        sign(sk, message)
        for sk, message in zip(private_keys, messages)
    ]

    agg_signature = aggregate(signatures)

    valid = verify_aggregate(
        public_keys, messages, agg_signature, proofs
    )

    print("Number of sensors:", len(sensors))
    print("Aggregate signature size:", len(agg_signature), "bytes")
    print("Aggregate verification:", valid)

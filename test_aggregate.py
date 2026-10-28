
from aggregate_signature import (
    keygen,
    sign,
    aggregate,
    verify_aggregate,
)


def create_test_batch(n=10):
    sensors = [keygen() for _ in range(n)]

    private_keys = [s[0] for s in sensors]
    public_keys = [s[1] for s in sensors]
    proofs = [s[2] for s in sensors]

    messages = [
        f"sensor-{i}:temperature={20+i}".encode()
        for i in range(n)
    ]

    signatures = [
        sign(sk, msg)
        for sk, msg in zip(private_keys, messages)
    ]

    agg_signature = aggregate(signatures)

    return public_keys, proofs, messages, agg_signature


def test_valid_aggregate():
    pks, proofs, messages, agg = create_test_batch()

    assert verify_aggregate(pks, messages, agg, proofs)


def test_modified_message_fails():
    pks, proofs, messages, agg = create_test_batch()

    messages[0] = b"sensor-0:temperature=999"

    assert not verify_aggregate(pks, messages, agg, proofs)


def test_wrong_public_key_fails():
    pks, proofs, messages, agg = create_test_batch()

    _, wrong_pk, wrong_pop = keygen()
    pks[0] = wrong_pk
    proofs[0] = wrong_pop

    assert not verify_aggregate(pks, messages, agg, proofs)

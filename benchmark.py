
import statistics
import time

from nacl.signing import SigningKey
from py_ecc.bls import G2ProofOfPossession as BLS

from aggregate_signature import keygen, sign, aggregate


SIZES = [2, 8, 32, 100]
REPEATS = 5


def average_ms(func, repeats=REPEATS):
    """Average elapsed time in milliseconds."""
    samples = []

    for _ in range(repeats):
        start = time.perf_counter()
        func()
        samples.append((time.perf_counter() - start) * 1000)

    return statistics.mean(samples)


def benchmark(n):
    messages = [
        f"sensor-{i}:temperature={20 + i}".encode()
        for i in range(n)
    ]

    # BLS keys and proofs
    sensors = [keygen() for _ in range(n)]
    sks = [s[0] for s in sensors]
    pks = [s[1] for s in sensors]
    proofs = [s[2] for s in sensors]

    # Ed25519 keys
    ed_keys = [SigningKey.generate() for _ in range(n)]
    ed_pks = [key.verify_key for key in ed_keys]

    # Precompute signatures outside timing
    bls_sigs = [sign(sk, msg) for sk, msg in zip(sks, messages)]
    agg_sig = aggregate(bls_sigs)

    ed_sigs = [
        key.sign(msg).signature
        for key, msg in zip(ed_keys, messages)
    ]

    # Validate correctness before benchmarking
    assert BLS.AggregateVerify(pks, messages, agg_sig)
    assert all(
        BLS.PopVerify(pk, pop)
        for pk, pop in zip(pks, proofs)
    )

    assert all(
        ed_pk.verify(msg, sig) == msg
        for ed_pk, msg, sig in zip(ed_pks, messages, ed_sigs)
    )

    # Per-message signing times
    bls_sign_ms = average_ms(
        lambda: [sign(sk, msg) for sk, msg in zip(sks, messages)]
    ) / n

    ed_sign_ms = average_ms(
        lambda: [key.sign(msg) for key, msg in zip(ed_keys, messages)]
    ) / n

    # Verification: individual signatures versus one BLS aggregate check
    bls_individual_verify_ms = average_ms(
        lambda: [
            BLS.Verify(pk, msg, sig)
            for pk, msg, sig in zip(pks, messages, bls_sigs)
        ]
    )

    bls_aggregate_verify_ms = average_ms(
        lambda: BLS.AggregateVerify(pks, messages, agg_sig)
    )

    ed_verify_ms = average_ms(
        lambda: [
            ed_pk.verify(msg, sig)
            for ed_pk, msg, sig in zip(ed_pks, messages, ed_sigs)
        ]
    )

    print(f"\nSensors: {n}")
    print(f"BLS signing per message: {bls_sign_ms:.4f} ms")
    print(f"Ed25519 signing per message: {ed_sign_ms:.4f} ms")
    print(f"BLS individual verification batch: {bls_individual_verify_ms:.4f} ms")
    print(f"BLS aggregate verification: {bls_aggregate_verify_ms:.4f} ms")
    print(f"Ed25519 individual verification batch: {ed_verify_ms:.4f} ms")
    print(f"One BLS signature size: {len(bls_sigs[0])} bytes")
    print(f"Aggregate BLS signature size: {len(agg_sig)} bytes")
    print(f"Total Ed25519 signatures size: {sum(map(len, ed_sigs))} bytes")


if __name__ == "__main__":
    for n in SIZES:
        benchmark(n)

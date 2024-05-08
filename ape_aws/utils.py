import ecdsa  # type: ignore[import]

SECP256_K1_N = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)


def _convert_der_to_rsv(signature: bytes, v_adjustment_factor: int = 0) -> dict:
    r, s = ecdsa.util.sigdecode_der(signature, ecdsa.SECP256k1.order)
    v = v_adjustment_factor
    if s > SECP256_K1_N / 2:
        s = SECP256_K1_N - s
    r = r.to_bytes(32, byteorder="big")
    s = s.to_bytes(32, byteorder="big")
    return dict(v=v, r=r, s=s)

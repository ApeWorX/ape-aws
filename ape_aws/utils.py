import ecdsa  # type: ignore[import]


def _convert_der_to_rsv(signature: bytes, v_adjustment_factor: int = 0) -> dict:
    r, s = ecdsa.util.sigdecode_der(signature, ecdsa.SECP256k1.order)
    if s > ecdsa.SECP256k1.order / 2:
        s = ecdsa.SECP256k1.order - s

    return dict(
        r=r.to_bytes(32, byteorder="big"),
        s=s.to_bytes(32, byteorder="big"),
        v=v_adjustment_factor,
    )

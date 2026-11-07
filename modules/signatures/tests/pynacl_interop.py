"""Independent framing + libsodium reference. Only public RFC test seeds used."""
import struct
import sys

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


def framed(purpose, message):
    return (b"KryptoCore/signatures\x00\x01" + struct.pack(">H", len(purpose))
            + purpose + struct.pack(">Q", len(message)) + message)


def main():
    public, signature, message = map(bytes.fromhex, sys.argv[1:4])
    purpose = sys.argv[4].encode("ascii")
    labels = (b"container-manifest/v1", b"release-manifest/v1", b"contact-binding/v1")
    assert purpose in labels
    other_purpose = next(label for label in labels if label != purpose)
    data = framed(purpose, message)
    VerifyKey(public).verify(data, signature)
    for changed in (data + b"\x00", framed(other_purpose, message)):
        try:
            VerifyKey(public).verify(changed, signature)
        except BadSignatureError:
            pass
        else:
            raise AssertionError("modified data was accepted")
    # RFC 8032 TEST 2, distinct from the Rust side's TEST 1 key.
    signer = SigningKey(bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))
    print((bytes(signer.verify_key) + signer.sign(data).signature).hex())


if __name__ == "__main__":
    main()

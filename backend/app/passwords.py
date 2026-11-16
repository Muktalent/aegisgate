"""Password hashing with scrypt (standard library, memory-hard).

Stored format:  scrypt$n=32768,r=8,p=3$<salt b64>$<hash b64>

The specification asks for Argon2id "or an equivalent contemporary scheme".
scrypt is used because it needs no extra dependency; the parameters follow
the OWASP password-storage recommendation (N=2^15, r=8, p=3). The parameters
are stored with each hash, so they can be raised later and old hashes still
verify; ``needs_rehash`` reports hashes made with weaker settings.
"""
import base64
import hashlib
import hmac
import secrets

SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 3
KEY_LENGTH = 32
SALT_LENGTH = 16
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          dklen=KEY_LENGTH, maxmem=256 * n * r + 1024 * 1024)


def validate_new_password(password: str) -> None:
    if not isinstance(password, str):
        raise ValueError("Password must be text.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must have at least {MIN_PASSWORD_LENGTH} characters.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must have at most {MAX_PASSWORD_LENGTH} characters.")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(SALT_LENGTH)
    digest = _derive(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return "scrypt$n={},r={},p={}${}${}".format(
        SCRYPT_N, SCRYPT_R, SCRYPT_P,
        base64.b64encode(salt).decode("ascii"), base64.b64encode(digest).decode("ascii"))


def _parse(stored: str) -> tuple[int, int, int, bytes, bytes]:
    scheme, params, salt, digest = stored.split("$")
    if scheme != "scrypt":
        raise ValueError("Unsupported scheme.")
    values = dict(item.split("=") for item in params.split(","))
    n, r, p = int(values["n"]), int(values["r"]), int(values["p"])
    if not (2 ** 10 <= n <= 2 ** 20 and n & (n - 1) == 0 and 1 <= r <= 32 and 1 <= p <= 16):
        raise ValueError("Parameters out of range.")
    return n, r, p, base64.b64decode(salt, validate=True), base64.b64decode(digest, validate=True)


def verify_password(password: str, stored: str) -> bool:
    """Constant-time comparison. Malformed stored values simply fail."""
    try:
        n, r, p, salt, expected = _parse(stored)
        actual = _derive(password, salt, n, r, p)
    except (ValueError, KeyError, TypeError, AttributeError):
        return False
    return hmac.compare_digest(actual, expected)


def needs_rehash(stored: str) -> bool:
    try:
        n, r, p, _, _ = _parse(stored)
    except (ValueError, KeyError, TypeError, AttributeError):
        return True
    return (n, r, p) != (SCRYPT_N, SCRYPT_R, SCRYPT_P)

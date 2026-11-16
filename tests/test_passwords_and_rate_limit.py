import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1] / "backend"))

from app import passwords
from app.rate_limit import FailureRateLimiter


@pytest.fixture(autouse=True)
def fast_hashing(monkeypatch):
    monkeypatch.setattr(passwords, "SCRYPT_N", 2 ** 12)


def test_hash_verifies_and_is_not_the_password():
    stored = passwords.hash_password("correct horse battery")
    assert stored.startswith("scrypt$n=4096,r=8,p=3$") and "correct horse" not in stored
    assert passwords.verify_password("correct horse battery", stored)
    assert not passwords.verify_password("correct horse batterx", stored)


def test_same_password_gets_different_salts():
    assert passwords.hash_password("correct horse battery") != passwords.hash_password("correct horse battery")


@pytest.mark.parametrize("stored", [
    "", "plain-text-password", "scrypt$n=4096,r=8,p=3$bad", "bcrypt$n=4096,r=8,p=3$AAAA$AAAA",
    "scrypt$n=8,r=8,p=3$AAAA$AAAA", "scrypt$n=4097,r=8,p=3$AAAA$AAAA",
    "scrypt$n=4096,r=8,p=3$not base64!$AAAA", None])
def test_malformed_stored_values_never_verify(stored):
    assert passwords.verify_password("anything", stored) is False


def test_needs_rehash_when_parameters_change(monkeypatch):
    stored = passwords.hash_password("correct horse battery")
    assert not passwords.needs_rehash(stored)
    monkeypatch.setattr(passwords, "SCRYPT_N", 2 ** 13)
    assert passwords.needs_rehash(stored) and passwords.verify_password("correct horse battery", stored)
    assert passwords.needs_rehash("garbage")


@pytest.mark.parametrize("password", ["short", "x" * 11, "x" * 129, None, 123456789012])
def test_new_password_policy_rejects(password):
    with pytest.raises(ValueError):
        passwords.validate_new_password(password)


def test_new_password_policy_accepts_unicode_passphrase():
    passwords.validate_new_password("contraseña larga ñ")
    assert passwords.verify_password("contraseña larga ñ", passwords.hash_password("contraseña larga ñ"))


def test_rate_limiter_blocks_after_max_failures_and_recovers():
    now = [1000.0]
    limiter = FailureRateLimiter(max_failures=3, window_seconds=60, clock=lambda: now[0])
    key = ("alice", "10.0.0.1")
    for _ in range(2):
        limiter.record_failure(key)
    assert limiter.retry_after(key) == 0
    limiter.record_failure(key)
    assert 1 <= limiter.retry_after(key) <= 61
    assert limiter.retry_after(("alice", "10.0.0.2")) == 0          # other client unaffected
    now[0] += 61
    assert limiter.retry_after(key) == 0


def test_rate_limiter_reset_and_validation():
    limiter = FailureRateLimiter(max_failures=1, window_seconds=60)
    limiter.record_failure("k")
    assert limiter.retry_after("k") > 0
    limiter.reset("k")
    assert limiter.retry_after("k") == 0
    limiter.record_failure("a"); limiter.reset()
    assert limiter.retry_after("a") == 0
    with pytest.raises(ValueError):
        FailureRateLimiter(max_failures=0)

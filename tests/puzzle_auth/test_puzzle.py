"""Tests para verificación de puzzle criptográfico (base, device, application)."""
import hashlib
import hmac
import os
import secrets
import time
import pytest
from base64 import b64encode
from unittest.mock import MagicMock
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from app.config import settings


# ── Helpers ─────────────────────────────────────────────────────────

def get_server_key():
    return hashlib.sha256(
        (settings.SECRET_KEY + "|puzzle_v1").encode("utf-8")
    ).digest()


def encrypt_aes(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext, iv


def build_valid_puzzle(key_hex: str) -> MagicMock:
    key = bytes.fromhex(key_hex)
    server_key = get_server_key()
    r2 = os.urandom(32)
    timestamp = int(time.time()).to_bytes(8, byteorder="big")
    p2 = hmac.new(key + server_key, r2 + timestamp, hashlib.sha256).digest()
    plaintext = p2 + r2 + timestamp
    ciphertext, iv = encrypt_aes(plaintext, key)
    puzzle = MagicMock()
    puzzle.encrypted_payload.ciphertext = b64encode(ciphertext).decode()
    puzzle.encrypted_payload.iv = b64encode(iv).decode()
    return puzzle


def build_expired_puzzle(key_hex: str) -> MagicMock:
    key = bytes.fromhex(key_hex)
    server_key = get_server_key()
    r2 = os.urandom(32)
    timestamp = int(time.time() - 120).to_bytes(8, byteorder="big")
    p2 = hmac.new(key + server_key, r2 + timestamp, hashlib.sha256).digest()
    plaintext = p2 + r2 + timestamp
    ciphertext, iv = encrypt_aes(plaintext, key)
    puzzle = MagicMock()
    puzzle.encrypted_payload.ciphertext = b64encode(ciphertext).decode()
    puzzle.encrypted_payload.iv = b64encode(iv).decode()
    return puzzle


def build_wrong_key_puzzle() -> MagicMock:
    wrong_key = os.urandom(32)
    server_key = get_server_key()
    r2 = os.urandom(32)
    timestamp = int(time.time()).to_bytes(8, byteorder="big")
    p2 = hmac.new(wrong_key + server_key, r2 + timestamp, hashlib.sha256).digest()
    plaintext = p2 + r2 + timestamp
    ciphertext, iv = encrypt_aes(plaintext, wrong_key)
    puzzle = MagicMock()
    puzzle.encrypted_payload.ciphertext = b64encode(ciphertext).decode()
    puzzle.encrypted_payload.iv = b64encode(iv).decode()
    return puzzle


def build_tampered_puzzle(key_hex: str) -> MagicMock:
    key = bytes.fromhex(key_hex)
    r2 = os.urandom(32)
    timestamp = int(time.time()).to_bytes(8, byteorder="big")
    fake_p2 = os.urandom(32)
    plaintext = fake_p2 + r2 + timestamp
    ciphertext, iv = encrypt_aes(plaintext, key)
    puzzle = MagicMock()
    puzzle.encrypted_payload.ciphertext = b64encode(ciphertext).decode()
    puzzle.encrypted_payload.iv = b64encode(iv).decode()
    return puzzle


def build_garbage_puzzle() -> MagicMock:
    puzzle = MagicMock()
    puzzle.encrypted_payload.ciphertext = b64encode(os.urandom(64)).decode()
    puzzle.encrypted_payload.iv = b64encode(os.urandom(16)).decode()
    return puzzle


DEVICE_KEY_HEX = secrets.token_hex(32)
APP_KEY_HEX = secrets.token_hex(32)
FAKE_ID = "00000000-0000-0000-0000-000000000001"


@dataclass
class FakeDevice:
    id: str = FAKE_ID
    encryption_key: str | None = DEVICE_KEY_HEX


@dataclass
class FakeApplication:
    id: str = FAKE_ID
    api_key: str | None = APP_KEY_HEX


# ── Tests PuzzleVerifier ────────────────────────────────────────────

class TestPuzzleVerifierValid:
    def test_valid_puzzle_returns_true(self):
        from app.shared.middleware.auth.auth_rc.puzzle import PuzzleVerifier
        verifier = PuzzleVerifier()
        result = verifier.verify(bytes.fromhex(DEVICE_KEY_HEX), build_valid_puzzle(DEVICE_KEY_HEX), FAKE_ID)
        assert result["valid"] is True


class TestPuzzleVerifierDecryptionFailed:
    def test_wrong_key_fails(self):
        from app.shared.middleware.auth.auth_rc.puzzle import PuzzleVerifier
        verifier = PuzzleVerifier()
        result = verifier.verify(bytes.fromhex(DEVICE_KEY_HEX), build_wrong_key_puzzle(), FAKE_ID)
        assert result["valid"] is False


class TestPuzzleVerifierTimestamp:
    def test_expired_timestamp_fails(self):
        from app.shared.middleware.auth.auth_rc.puzzle import PuzzleVerifier
        verifier = PuzzleVerifier()
        result = verifier.verify(bytes.fromhex(DEVICE_KEY_HEX), build_expired_puzzle(DEVICE_KEY_HEX), FAKE_ID)
        assert result["valid"] is False


class TestPuzzleVerifierTampered:
    def test_tampered_p2_fails(self):
        from app.shared.middleware.auth.auth_rc.puzzle import PuzzleVerifier
        verifier = PuzzleVerifier()
        result = verifier.verify(bytes.fromhex(DEVICE_KEY_HEX), build_tampered_puzzle(DEVICE_KEY_HEX), FAKE_ID)
        assert result["valid"] is False


class TestPuzzleVerifierGarbage:
    def test_garbage_payload_fails(self):
        from app.shared.middleware.auth.auth_rc.puzzle import PuzzleVerifier
        verifier = PuzzleVerifier()
        result = verifier.verify(bytes.fromhex(DEVICE_KEY_HEX), build_garbage_puzzle(), FAKE_ID)
        assert result["valid"] is False


# ── Tests DeviceAuth ────────────────────────────────────────────────

class TestDeviceAuthValid:
    def test_valid_puzzle(self):
        from app.shared.middleware.auth.auth_rc.device import DeviceAuth
        result = DeviceAuth().authenticate(FakeDevice(), build_valid_puzzle(DEVICE_KEY_HEX))
        assert result["valid"] is True

    def test_auth_type_is_rc(self):
        from app.shared.middleware.auth.auth_rc.device import DeviceAuth
        assert DeviceAuth().get_auth_type() == "rc"


class TestDeviceAuthNoKey:
    def test_no_key_fails(self):
        from app.shared.middleware.auth.auth_rc.device import DeviceAuth
        result = DeviceAuth().authenticate(FakeDevice(encryption_key=None), build_valid_puzzle(DEVICE_KEY_HEX))
        assert result["valid"] is False


class TestDeviceAuthWrongKey:
    def test_wrong_key_fails(self):
        from app.shared.middleware.auth.auth_rc.device import DeviceAuth
        result = DeviceAuth().authenticate(FakeDevice(), build_wrong_key_puzzle())
        assert result["valid"] is False


# ── Tests ApplicationAuth ───────────────────────────────────────────

class TestApplicationAuthValid:
    def test_valid_puzzle(self):
        from app.shared.middleware.auth.auth_rc.application import ApplicationAuth
        result = ApplicationAuth().authenticate(FakeApplication(), build_valid_puzzle(APP_KEY_HEX))
        assert result["valid"] is True

    def test_auth_type_is_rc(self):
        from app.shared.middleware.auth.auth_rc.application import ApplicationAuth
        assert ApplicationAuth().get_auth_type() == "rc"


class TestApplicationAuthNoKey:
    def test_no_key_fails(self):
        from app.shared.middleware.auth.auth_rc.application import ApplicationAuth
        result = ApplicationAuth().authenticate(FakeApplication(api_key=None), build_valid_puzzle(APP_KEY_HEX))
        assert result["valid"] is False


class TestApplicationAuthWrongKey:
    def test_wrong_key_fails(self):
        from app.shared.middleware.auth.auth_rc.application import ApplicationAuth
        result = ApplicationAuth().authenticate(FakeApplication(), build_wrong_key_puzzle())
        assert result["valid"] is False

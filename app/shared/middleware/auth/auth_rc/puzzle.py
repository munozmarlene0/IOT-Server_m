"""
PuzzleVerifier — verificador de puzzle criptográfico.
AES-256-CBC + HMAC-SHA256 con timestamp oculto.

Solo se encarga del reto criptográfico.
Recibe la clave como bytes, no sabe de qué entidad viene.
"""

import hashlib
import hmac
import logging
import time
from base64 import b64decode

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from app.config import settings

logger = logging.getLogger(__name__)

TIMESTAMP_WINDOW = 60  # segundos de tolerancia


class PuzzleVerifier:
    """
    Verificador genérico de puzzle criptográfico.
    Recibe la clave ya como bytes — no conoce la entidad de origen.
    """

    def __init__(self):
        self.server_key = hashlib.sha256(
            (settings.SECRET_KEY + "|puzzle_v1").encode("utf-8")
        ).digest()

    def _decrypt_payload(self, ciphertext_b64: str, iv_b64: str, key: bytes) -> bytes:
        """Descifrar AES-256-CBC con PKCS7 unpadding."""
        ciphertext = b64decode(ciphertext_b64)
        iv = b64decode(iv_b64)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    def verify(self, entity_key: bytes, puzzle, entity_id: str) -> dict:
        """
        Verificar puzzle criptográfico.

        Args:
            entity_key: clave AES de 32 bytes (ya convertida)
            puzzle: objeto con encrypted_payload.ciphertext y .iv
            entity_id: string para identificar en logs

        Flujo:
            1. Descifrar payload
            2. Separar componentes (P2 + R2 + timestamp)
            3. Verificar timestamp
            4. Recalcular P2
            5. Comparar (timing-safe)
        """
        # 1. Descifrar payload
        try:
            decrypted = self._decrypt_payload(
                puzzle.encrypted_payload.ciphertext,
                puzzle.encrypted_payload.iv,
                entity_key,
            )
        except Exception:
            logger.warning(f"Puzzle failed for {entity_id}: decryption failed")
            return {"valid": False, "error": "Authentication failed"}

        # 2. Separar componentes: P2 (32) + R2 (32) + timestamp (8) = 72 bytes
        if len(decrypted) < 72:
            logger.warning(f"Puzzle failed for {entity_id}: invalid payload length")
            return {"valid": False, "error": "Authentication failed"}

        p2_received = decrypted[:32]
        r2 = decrypted[32:64]
        timestamp_bytes = decrypted[64:72]

        # 3. Verificar timestamp
        ts_now = time.time()
        ts_puzzle = int.from_bytes(timestamp_bytes, byteorder="big")
        if abs(ts_puzzle - ts_now) > TIMESTAMP_WINDOW:
            logger.warning(f"Puzzle failed for {entity_id}: timestamp expired")
            return {"valid": False, "error": "Authentication failed"}

        # 4. Recalcular P2
        p2_expected = hmac.new(
            entity_key + self.server_key,
            r2 + timestamp_bytes,
            hashlib.sha256,
        ).digest()

        # 5. Comparar (timing-safe)
        if hmac.compare_digest(p2_received, p2_expected):
            return {"valid": True}
        else:
            logger.warning(f"Puzzle failed for {entity_id}: P2 mismatch")
            return {"valid": False, "error": "Authentication failed"}

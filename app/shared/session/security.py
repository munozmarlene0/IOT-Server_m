import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from jose import jwe
from jose.exceptions import JWEError


class JWEHandler:
    def __init__(self, encryption_key: str):
        try:
            key_bytes = base64.b64decode(encryption_key)
        except Exception as e:
            raise ValueError(f"ENCRYPTION_KEY must be valid base64: {e}")
        
        if len(key_bytes) != 32:
            raise ValueError(
                f"ENCRYPTION_KEY must be exactly 32 bytes when decoded, got {len(key_bytes)} bytes"
            )
        
        self.encryption_key = key_bytes
    
    def encrypt(self, claims: Dict[str, Any], ttl_minutes: int = 30) -> str:
        now = datetime.now(timezone.utc)
        exp_timestamp = int((now + timedelta(minutes=ttl_minutes)).timestamp())
        iat_timestamp = int(now.timestamp())
        
        claims_with_timestamps = {
            **claims,
            "exp": exp_timestamp,
            "iat": iat_timestamp,
        }
        
        payload_json = json.dumps(claims_with_timestamps)
        
        encrypted = jwe.encrypt(
            plaintext=payload_json.encode(),
            key=self.encryption_key,
            algorithm="dir",
            encryption="A256GCM",
        )
        
        if isinstance(encrypted, bytes):
            return encrypted.decode()
        return encrypted
    
    def decrypt(self, token: str) -> Dict[str, Any]:
        decrypted = jwe.decrypt(token.encode(), self.encryption_key)
        
        try:
            claims = json.loads(decrypted.decode())
        except json.JSONDecodeError as e:
            raise JWEError(f"Invalid JSON payload in token: {e}")
        
        # Verify expiration internally
        if not self.verify_expiration(claims):
            raise JWEError("Token has expired")
        
        return claims
    
    def verify_expiration(self, claims: Dict[str, Any]) -> bool:
        exp = claims.get("exp")
        if not exp or not isinstance(exp, (int, float)):
            return False
        
        now_timestamp = int(datetime.now(timezone.utc).timestamp())
        return exp > now_timestamp

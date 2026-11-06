"""Generate fresh secrets for a .env file. Usage: python generate_secrets.py >> backend/.env

Never commit the output. In production, load these from a secret manager instead of a file."""
import base64
import os
import secrets

print(f"DATA_ENCRYPTION_KEY={base64.b64encode(os.urandom(32)).decode()}")
print(f"AUDIT_HMAC_KEY={base64.b64encode(os.urandom(32)).decode()}")
print(f"POSTGRES_PASSWORD={secrets.token_urlsafe(24)}")
print(f"APP_DB_PASSWORD={secrets.token_urlsafe(24)}")

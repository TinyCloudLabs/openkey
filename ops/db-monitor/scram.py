#!/usr/bin/env python3
"""Print the SCRAM-SHA-256 verifier for the password in OPENKEY_MONITOR_PW.

provision.sql sends the verifier, not the password, in the PASSWORD clause. A server that logs statements
(log_statement = ddl, mod or all) then logs a salted hash of a random 48-character password, never the password
itself. PostgreSQL accepts a ready-made verifier whatever password_encryption is set to, and the role logs in with
the password as usual.
"""
import base64
import hashlib
import hmac
import os
import sys

ITERATIONS = 4096


def verifier(password: str) -> str:
    salt = os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda raw: base64.b64encode(raw).decode()
    return f"SCRAM-SHA-256${ITERATIONS}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"


if __name__ == "__main__":
    pw = os.environ.get("OPENKEY_MONITOR_PW")
    if not pw:
        sys.exit("OPENKEY_MONITOR_PW is not set")
    if not pw.isascii():
        sys.exit("OPENKEY_MONITOR_PW must be ASCII")
    print(verifier(pw))

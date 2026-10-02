from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from daedalus.config import APP_ENV, ENCRYPTION_KEY


class CredentialEncryptionError(RuntimeError):
    pass


def encryption_available() -> bool:
    return bool(ENCRYPTION_KEY) or APP_ENV != "production"


def _load_local_key() -> bytes:
    key_path = Path(
        os.environ.get(
            "DAEDALUS_DEV_ENCRYPTION_KEY_FILE",
            "data/daedalus-encryption.key",
        )
    ).expanduser()
    key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        key_path.parent.chmod(0o700)
    except OSError:
        pass

    try:
        descriptor = os.open(
            key_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        try:
            key = key_path.read_bytes()
            key_path.chmod(0o600)
            return key
        except OSError as exc:
            raise CredentialEncryptionError(
                "The local integration key cannot be read."
            ) from exc

    key = Fernet.generate_key()
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(key)
        handle.flush()
        os.fsync(handle.fileno())
    return key


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    if ENCRYPTION_KEY:
        try:
            key = ENCRYPTION_KEY.encode("ascii")
            return Fernet(key)
        except (UnicodeEncodeError, ValueError) as exc:
            raise CredentialEncryptionError(
                "DAEDALUS_ENCRYPTION_KEY is not a valid Fernet key."
            ) from exc
    if APP_ENV == "production":
        raise CredentialEncryptionError(
            "Set DAEDALUS_ENCRYPTION_KEY before connecting an integration."
        )
    try:
        return Fernet(_load_local_key())
    except (ValueError, OSError) as exc:
        raise CredentialEncryptionError(
            "The local integration encryption key is invalid."
        ) from exc


def encrypt_secret(value: str) -> str:
    try:
        return _fernet().encrypt(value.encode("utf-8")).decode("ascii")
    except CredentialEncryptionError:
        raise
    except Exception as exc:
        raise CredentialEncryptionError("The integration key could not be encrypted.") from exc


def decrypt_secret(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise CredentialEncryptionError(
            "The integration key cannot be decrypted. Restore the key used to encrypt it."
        ) from exc
    except CredentialEncryptionError:
        raise
    except Exception as exc:
        raise CredentialEncryptionError("The stored integration key is invalid.") from exc

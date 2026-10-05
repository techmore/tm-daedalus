#!/usr/bin/env python3
"""Seal or restore a private recovery-secret file without printing its contents."""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import stat
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAX_SECRET_BYTES = 1024 * 1024
MAX_ENVELOPE_BYTES = 2 * MAX_SECRET_BYTES


def _key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or not 12 <= len(password) <= 1024:
        raise ValueError('Use a recovery password of 12 to 1024 characters.')
    return base64.urlsafe_b64encode(Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(password.encode()))


def seal(contents: bytes, password: str) -> bytes:
    if not contents or len(contents) > MAX_SECRET_BYTES:
        raise ValueError('Recovery secrets must be nonempty and at most 1 MiB.')
    salt = os.urandom(16)
    token = Fernet(_key(password, salt)).encrypt(contents)
    return json.dumps({'version': 1, 'format': 'daedalus-recovery-secrets', 'salt': base64.b64encode(salt).decode(), 'token': token.decode()}, separators=(',', ':')).encode()


def unseal(envelope: bytes, password: str) -> bytes:
    if len(envelope) > MAX_ENVELOPE_BYTES:
        raise ValueError('Recovery envelope exceeds the size limit.')
    try:
        value = json.loads(envelope)
        if not isinstance(value, dict) or set(value) != {'version', 'format', 'salt', 'token'} or type(value['version']) is not int or value['version'] != 1 or value['format'] != 'daedalus-recovery-secrets':
            raise ValueError()
        salt = base64.b64decode(value['salt'], validate=True)
        if len(salt) != 16 or not isinstance(value['token'], str):
            raise ValueError()
        contents = Fernet(_key(password, salt)).decrypt(value['token'].encode())
        if not contents or len(contents) > MAX_SECRET_BYTES:
            raise ValueError()
        return contents
    except (ValueError, TypeError, KeyError, UnicodeError, InvalidToken) as exc:
        raise ValueError('Recovery envelope or password is invalid.') from exc


def read_private(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077 or metadata.st_size > limit:
            raise ValueError('Input must be an owned private regular file within the size limit.')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            contents = source.read(limit + 1)
        if len(contents) > limit:
            raise ValueError('Input exceeds the size limit.')
        return contents
    finally:
        os.close(fd)


def write_new_private(path: Path, contents: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as destination:
            destination.write(contents)
            destination.flush()
            os.fsync(fd)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('seal', 'restore'))
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    try:
        if not sys.stdin.isatty():
            raise ValueError('Run this command in an interactive terminal for a private password prompt.')
        source = read_private(args.source, MAX_SECRET_BYTES if args.operation == 'seal' else MAX_ENVELOPE_BYTES)
        password = getpass.getpass('Recovery password: ')
        if args.operation == 'seal':
            if password != getpass.getpass('Confirm recovery password: '):
                raise ValueError('Recovery passwords do not match.')
            output = seal(source, password)
        else:
            output = unseal(source, password)
        write_new_private(args.destination, output)
    except (OSError, ValueError) as exc:
        parser.exit(1, f'Recovery operation refused: {exc}\n')
    print(f'Private recovery file written: {args.destination}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

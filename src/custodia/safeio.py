"""Bounded local artifacts. Fontem conserva; nomina ne divulga."""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import stat
import tempfile

JSON_LIMIT = 16 * 1024 * 1024
INPUT_LIMIT = 128 * 1024 * 1024


class Invalid(ValueError):
    """A sanitized error safe for a terminal."""


def canonical(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError, RecursionError):
        raise Invalid("Unsupported JSON value.") from None


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Invalid("Duplicate JSON key.")
        result[key] = value
    return result


def _constant(value):
    raise Invalid("Nonfinite JSON number.")


def _float(value):
    result = float(value)
    if not math.isfinite(result):
        raise Invalid("Nonfinite JSON number.")
    return result


def parse(raw: bytes, limit: int = JSON_LIMIT) -> object:
    if len(raw) > limit:
        raise Invalid("JSON artifact exceeds its size limit.")
    # Altitudo quoque finitur; magnitudo sola non sufficit.
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 128:
                raise Invalid("JSON nesting exceeds its depth limit.")
        elif byte in (93, 125):
            depth -= 1
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float)
    except (UnicodeError, ValueError, RecursionError):
        raise Invalid("Invalid bounded UTF-8 JSON artifact.") from None


def open_regular(path: Path):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        stream = os.fdopen(fd, "rb")
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            stream.close()
            raise Invalid("Input must be a regular file, not a symlink or special file.")
        return stream
    except OSError:
        raise Invalid("Cannot open a regular input file.") from None


def read(path: Path, limit: int = JSON_LIMIT) -> bytes:
    with open_regular(path) as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise Invalid("Input exceeds its size limit.")
    return raw


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def hash_file(path: Path, limit: int = INPUT_LIMIT) -> tuple[str, int]:
    sha, size = hashlib.sha256(), 0
    with open_regular(path) as stream:
        while block := stream.read(1024 * 1024):
            size += len(block)
            if size > limit:
                raise Invalid("Input exceeds its size limit.")
            sha.update(block)
    return sha.hexdigest(), size


def new_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except OSError:
        raise Invalid("Output must be a new directory in a writable, trusted parent.") from None


def write_new(path: Path, raw: bytes) -> None:
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".custodia-", dir=path.parent)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    except OSError:
        raise Invalid("Cannot publish artifact without overwriting an existing path.") from None
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def snapshot(source: Path, target: Path) -> dict:
    sha, size, temporary = hashlib.sha256(), 0, None
    try:
        with open_regular(source) as stream:
            before = os.fstat(stream.fileno())
            if before.st_size > INPUT_LIMIT:
                raise Invalid("Input exceeds the 128 MiB snapshot limit.")
            fd, temporary = tempfile.mkstemp(prefix=".custodia-input-", dir=target.parent)
            with os.fdopen(fd, "wb") as output:
                while block := stream.read(1024 * 1024):
                    size += len(block)
                    if size > INPUT_LIMIT:
                        raise Invalid("Input exceeded the snapshot limit while reading.")
                    sha.update(block)
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
            after = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or size != before.st_size:
                raise Invalid("Input changed during snapshot creation.")
            os.link(temporary, target)
        return {"sha256": sha.hexdigest(), "bytes": size, "artifact": "input.bin"}
    except OSError:
        raise Invalid("Snapshot creation failed.") from None
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass

"""Content identities for the trusted adapter and Java runtime."""

import hashlib
import os
from pathlib import Path
import re
import stat

from .safeio import Invalid, canonical, hash_file, read


def engine_identity() -> str:
    root = Path(__file__).resolve().parent
    records = []
    for path in sorted(root.rglob("*")):
        if path.suffix in (".py", ".java") and path.is_file():
            sha, size = hash_file(path)
            records.append([path.relative_to(root).as_posix(), sha, size])
    return hashlib.sha256(canonical(records)).hexdigest()


def java_identity(root: Path) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise Invalid("Java home must be a regular trusted JDK directory.")
    for component in ("bin/java", "bin/javac", "release"):
        if not (root / component).is_file():
            raise Invalid("Java home must contain a full JDK, including javac and release metadata.")
    root = root.resolve(strict=True)
    sha = hashlib.sha256(b"custodia-java-tree-v1\0")
    count = total = 0
    for directory, subdirs, filenames in os.walk(root, followlinks=False):
        subdirs.sort()
        for name in sorted(subdirs + filenames):
            path = Path(directory, name)
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                target = path.resolve(strict=True)
                if not target.is_relative_to(root):
                    raise Invalid("JDK symlinks must remain inside the selected runtime.")
                data = [relative, "symlink", os.readlink(path)]
            elif stat.S_ISDIR(info.st_mode):
                continue
            elif stat.S_ISREG(info.st_mode):
                value, size = hash_file(path, 1024 * 1024 * 1024)
                total += size
                data = [relative, "file", value, size, info.st_mode & 0o111]
            else:
                raise Invalid("JDK contains a special file.")
            count += 1
            if count > 100000 or total > 4 * 1024**3:
                raise Invalid("JDK identity scan exceeds its limits.")
            sha.update(canonical(data))
    release = read(root / "release", 65536)
    match = re.search(rb'(?m)^JAVA_VERSION="([A-Za-z0-9._+\-]{1,64})"$', release)
    if not match:
        raise Invalid("JDK release version is not recognized.")
    return {"name": "java", "version": match.group(1).decode(), "tree_sha256": sha.hexdigest(), "file_count": count, "size_bytes": total}

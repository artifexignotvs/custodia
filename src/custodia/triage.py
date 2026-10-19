"""Static byte observations; run inside the analysis boundary."""

from __future__ import annotations

import hashlib
import math
import struct
from pathlib import Path


def _header(header: bytes, size: int) -> dict:
    result = {"format": "unknown", "architecture": "unknown", "header_status": "unrecognized"}
    if header[:4] == b"\x7fELF":
        result["format"] = "ELF"
        if len(header) < 52 or header[4] not in (1, 2) or header[5] not in (1, 2):
            result["header_status"] = "malformed_or_truncated"
            return result
        bits, endian = (32 if header[4] == 1 else 64), ("<" if header[5] == 1 else ">")
        if len(header) < (52 if bits == 32 else 64):
            result["header_status"] = "malformed_or_truncated"
            return result
        machine = struct.unpack_from(endian + "H", header, 18)[0]
        result.update(bits=bits, byte_order="little" if endian == "<" else "big", machine=machine, architecture={3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64", 243: "RISC-V"}.get(machine, "unknown"), entry_point=hex(struct.unpack_from(endian + ("I" if bits == 32 else "Q"), header, 24)[0]), header_status="observed")
    elif header[:2] == b"MZ":
        result.update(format="PE-candidate", header_status="not_fully_parsed")
        if len(header) >= 64:
            offset = struct.unpack_from("<I", header, 60)[0]
            if offset + 24 <= len(header) and header[offset:offset + 4] == b"PE\0\0":
                machine, sections = struct.unpack_from("<HH", header, offset + 4)
                result.update(format="PE", machine=machine, architecture={0x14c: "x86", 0x8664: "x86-64", 0xaa64: "AArch64"}.get(machine, "unknown"), declared_sections=sections, header_status="observed")
    elif header[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        result.update(format="Mach-O-candidate", header_status="magic_only")
    elif header[:4] == b"\0asm":
        result.update(format="WebAssembly", header_status="observed" if len(header) >= 8 else "truncated", declared_version=int.from_bytes(header[4:8], "little") if len(header) >= 8 else None)
    elif header[:4] == b"PK\x03\x04":
        result.update(format="ZIP-candidate", header_status="magic_only")
    return result


def inspect(path: Path, max_strings: int = 400, string_limit: int = 160) -> dict:
    sha = hashlib.sha256()
    counts, size, header = [0] * 256, 0, b""
    strings, current, start, total_strings, clipped = [], bytearray(), 0, 0, False

    def finish():
        nonlocal total_strings, clipped, current
        if len(current) >= 6:
            total_strings += 1
            if len(strings) < max_strings:
                strings.append({"offset": start, "value": current[:string_limit].decode("ascii"), "truncated": len(current) > string_limit})
            else:
                clipped = True
        current = bytearray()

    with path.open("rb") as stream:
        while block := stream.read(65536):
            if not header:
                header = block
            sha.update(block)
            for byte in block:
                counts[byte] += 1
                if 32 <= byte <= 126:
                    if not current:
                        start = size
                    if len(current) <= string_limit:
                        current.append(byte)
                else:
                    finish()
                size += 1
        finish()
    entropy = -sum((count / size) * math.log2(count / size) for count in counts if count) if size else 0.0
    return {"schema": "custodia.triage.v1", "sha256": sha.hexdigest(), "bytes": size, **_header(header, size), "entropy_bits_per_byte": round(entropy, 6), "ascii_strings": strings, "ascii_runs_at_least_6": total_strings, "string_list_truncated": clipped, "string_limit": string_limit, "observation_scope": "byte_statistics_and_bounded_headers", "classification": "not_performed", "target_executed": False}

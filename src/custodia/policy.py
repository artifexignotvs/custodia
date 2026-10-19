"""Explicit, finite analysis policy."""

from dataclasses import asdict, dataclass

from .safeio import Invalid, canonical, digest


@dataclass(frozen=True)
class Policy:
    memory_mib: int = 2048
    pids: int = 128
    cpu_percent: int = 100
    wall_seconds: int = 180
    scratch_mib: int = 512
    output_bytes: int = 8 * 1024 * 1024
    max_functions: int = 1000
    decompile_count: int = 3
    decompile_seconds: int = 10
    analysis_seconds: int = 120

    def __post_init__(self):
        bounds = {"memory_mib": (128, 8192), "pids": (16, 512), "cpu_percent": (1, 400), "wall_seconds": (5, 3600), "scratch_mib": (16, 2048), "output_bytes": (65536, 16 * 1024 * 1024), "max_functions": (1, 1000), "decompile_count": (0, 10), "decompile_seconds": (1, 60), "analysis_seconds": (1, 3600)}
        for key, (low, high) in bounds.items():
            value = getattr(self, key)
            if type(value) is not int or not low <= value <= high:
                raise Invalid(f"Policy field {key} must be an integer from {low} to {high}.")
        if self.scratch_mib >= self.memory_mib:
            raise Invalid("Scratch capacity must be smaller than the aggregate memory limit.")

    @property
    def document(self):
        return {"schema": "custodia.policy.v1", **asdict(self)}

    @property
    def sha256(self):
        return digest(canonical(self.document))

    def ghidra_config(self):
        return {"max_functions": self.max_functions, "decompile_count": self.decompile_count, "decompile_seconds": self.decompile_seconds, "analysis_seconds": min(self.analysis_seconds, self.wall_seconds), "heap_mb": min(4096, max(256, self.memory_mib - self.scratch_mib - 384))}


def from_document(document: object) -> Policy:
    if not isinstance(document, dict) or document.get("schema") != "custodia.policy.v1" or set(document) != set(Policy().document):
        raise Invalid("Unknown or incomplete analysis policy.")
    return Policy(**{k: v for k, v in document.items() if k != "schema"})

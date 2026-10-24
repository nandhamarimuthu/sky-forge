"""Reconstruct redacted patch context from the original scan, never from user-supplied secret values."""

from __future__ import annotations

import re

from app.adapters.repository.git_repo import RepoWorkspace
from app.core.security import redact

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class PatchReconstructionError(ValueError):
    pass


def restore_patch_context(ws: RepoWorkspace, diff: str) -> str:
    """Restore only old/context lines at exact hunk coordinates after checking their redacted representation."""
    if "[REDACTED]" not in diff:
        return diff
    output: list[str] = []
    source: list[str] = []
    old_left = new_left = 0
    old_index = 0
    for line in diff.splitlines(keepends=True):
        if old_left or new_left:
            prefix = line[:1]
            if prefix == "\\":
                output.append(line)
                continue
            if prefix not in (" ", "-", "+"):
                raise PatchReconstructionError("Malformed patch hunk; re-scan to regenerate this proposal")
            if prefix in (" ", "-"):
                if old_left <= 0 or not 0 <= old_index < len(source):
                    raise PatchReconstructionError("Patch no longer matches its source file; re-scan the project")
                original = source[old_index].removesuffix("\n")
                stored = line[1:].removesuffix("\n")
                if original != stored:
                    if redact(original) != stored:
                        raise PatchReconstructionError("Patch context changed since the scan; re-scan the project")
                    line = prefix + original + ("\n" if line.endswith("\n") else "")
                old_index += 1
                old_left -= 1
            if prefix in (" ", "+"):
                if new_left <= 0:
                    raise PatchReconstructionError("Malformed patch hunk; re-scan to regenerate this proposal")
                if prefix == "+" and "[REDACTED]" in line:
                    raise PatchReconstructionError("An added line is redacted; re-scan to regenerate a safe patch")
                new_left -= 1
        elif line.startswith("--- "):
            path = line[4:].strip()
            source = [] if path == "/dev/null" else ws.read_text(path.removeprefix("a/")).splitlines(keepends=True)
        elif match := _HUNK.match(line):
            old_index = int(match[1]) - 1
            old_left = int(match[2]) if match[2] is not None else 1
            new_left = int(match[4]) if match[4] is not None else 1
        output.append(line)
    if old_left or new_left:
        raise PatchReconstructionError("Incomplete patch hunk; re-scan to regenerate this proposal")
    restored = "".join(output)
    if redact(restored) != diff:
        raise PatchReconstructionError("Reconstructed patch differs from the reviewed change")
    return restored

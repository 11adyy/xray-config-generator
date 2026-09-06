from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Iterable


def validate_json_files(paths: Iterable[Path]) -> list[str]:
    errors: list[str] = []
    for path in paths:
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"{path}: {exc}")
    return errors


def validate_with_xray(config_paths: Iterable[Path], xray_bin: str = "xray") -> list[str]:
    errors: list[str] = []
    exe = shutil.which(xray_bin) if "/" not in xray_bin else xray_bin
    if not exe or not Path(exe).exists():
        return [f"xray binary not found: {xray_bin}"]
    for path in config_paths:
        proc = subprocess.run(
            [exe, "run", "-test", "-config", str(path)],
            text=True,
            capture_output=True,
        )
        if proc.returncode != 0:
            msg = (proc.stderr or proc.stdout).strip()
            errors.append(f"{path}: {msg}")
    return errors

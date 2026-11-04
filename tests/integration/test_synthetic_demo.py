from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_synthetic_demo_detects_and_resolves_mock_finding():
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, str(root / "examples" / "synthetic_demo.py")],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "detected critical confirmed finding" in result.stdout
    assert "no confirmed findings" in result.stdout
    assert "Report target host: 127.0.0.1" in result.stdout

"""Installation regressions: real wheel resources, not the checkout's cwd."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import zipfile

import pytest

from memrot.smoke import run_smoke

ROOT = Path(__file__).resolve().parents[1]


def test_smoke_is_offline_even_with_presidio_configured(monkeypatch, tmp_path):
    attempts = []

    def fail_network(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("offline smoke attempted network access")

    monkeypatch.setenv("PRESIDIO_API_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("MEMROT_TIER_STRICT", "1")
    monkeypatch.setattr(socket.socket, "connect", fail_network)
    monkeypatch.setattr(socket.socket, "connect_ex", fail_network)
    monkeypatch.setattr(socket, "getaddrinfo", fail_network)
    monkeypatch.chdir(tmp_path)
    result = run_smoke()
    assert not attempts  # also catch connection errors swallowed by a fallback
    assert result["status"] == "ok"
    assert result["outcomes"] == {"persistent": "CONFIRMED", "nonpersistent": "CLEAN"}
    assert result["catalog_files"] == 26
    assert result["lifecycle_events"] > 0


@pytest.fixture(scope="module")
def installed_wheel(tmp_path_factory):
    directory = tmp_path_factory.mktemp("wheel-install")
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(directory), str(ROOT)],
        check=True, capture_output=True, text=True, timeout=60,
    )
    wheel, = directory.glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    assert not any(name.startswith(("tests/", "memory_trace/tests/")) for name in names)
    assert "mcp_audit/data/lexicon.json" in names
    assert "memrot/catalog/imported/garak_dan/NOTICE.md" in names
    assert "memrot/catalog/imported/trustairlab_jailbreak/sample.json" in names
    for resource_dir in ("schemas", "profiles"):
        for source in (ROOT / resource_dir).glob("*.json"):
            assert f"memrot_data/{resource_dir}/{source.name}" in names
    for source in (ROOT / "memrot/catalog").rglob("*.json"):
        assert source.relative_to(ROOT).as_posix() in names
    site = directory / "site"
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-deps", "--no-index", "--no-cache-dir",
         "--target", str(site), str(wheel)],
        check=True, capture_output=True, text=True, timeout=60,
    )
    return directory, site


@pytest.mark.parametrize("module", ["memrot", "mcp_audit", "memrot.smoke"])
def test_installed_wheel_runs_outside_checkout(installed_wheel, module):
    directory, site = installed_wheel
    # -I ignores PYTHONPATH and cwd. Prepend the wheel install ahead of any
    # editable installation in this interpreter's site-packages.
    code = """
import pathlib, runpy, sys
site = pathlib.Path(sys.argv.pop(1))
sys.path.insert(0, str(site))
import memrot, mcp_audit, memory_trace, memrot_data
for package in (memrot, mcp_audit, memory_trace, memrot_data):
    assert pathlib.Path(package.__file__).is_relative_to(site), package.__file__
module = sys.argv.pop(1)
sys.argv[0] = module
runpy.run_module(module, run_name='__main__')
"""
    env = dict(os.environ, PRESIDIO_API_URL="http://127.0.0.1:1")
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, str(site), module]
        + ([] if module == "memrot.smoke" else ["--help"]),
        cwd=directory, env=env, capture_output=True, text=True, check=True, timeout=30,
    )
    if module == "memrot.smoke":
        assert json.loads(result.stdout)["status"] == "ok"
    else:
        assert "usage:" in result.stdout

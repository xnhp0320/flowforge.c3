"""Backend selection must use parsed variables, including comments."""
import os
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def run(tmp_path):
    binary = Path(os.environ.get("FFG_RUNTIME", "build/ffg")).resolve()
    def invoke(source, *args):
        program = tmp_path / "case.packet"
        program.write_text(source)
        return subprocess.run([str(binary), str(program), *args], capture_output=True, text=True, timeout=5)
    return invoke


def test_commented_dpdk_does_not_select_live_runtime(run):
    result = run('# DPDK_ARGS: "-l 0"\n# BACKEND: "dpdk"\nPACKET: Ether()/IP()/UDP()')
    assert result.returncode == 0, result.stderr
    assert "runtime completed" not in result.stdout


def test_commented_backend_switch_and_inline_comments(run):
    result = run('BACKEND: "tap" # chosen\nINTERFACE: "fftest0"\n# BACKEND: "dpdk"\n# DPDK_ARGS: "-l 0"\nPACKET: Ether()/IP()/UDP()', '--check')
    assert result.returncode == 0, result.stderr
    assert "check ok" in result.stdout


def test_duplicate_active_backend_rejected(run):
    result = run('BACKEND: "tap"\nBACKEND: "dpdk"\nINTERFACE: "fftest0"\nPACKET: Ether()', '--check')
    assert result.returncode != 0
    assert "duplicate variable 'BACKEND'" in result.stderr


def test_backend_text_inside_string_is_not_configuration(run):
    result = run('NOTE: "# DPDK_ARGS: BACKEND:"\nPACKET: Ether()/IP()/UDP()')
    assert result.returncode == 0, result.stderr
    assert "runtime completed" not in result.stdout


def test_backend_cli_option_is_not_supported(run):
    result = run('PACKET: Ether()', '--backend', 'tap')
    assert result.returncode != 0


def test_invalid_backend_has_diagnostic(run):
    result = run('BACKEND: "invalid"\nPACKET: Ether()', '--check')
    assert result.returncode != 0
    assert "BACKEND must be" in result.stderr

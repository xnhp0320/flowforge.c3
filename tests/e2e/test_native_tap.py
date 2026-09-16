"""Linux native TAP lifecycle, multiqueue receive and error paths."""
import os
import socket
import subprocess
import time

import pytest
from scapy.all import Ether, IP, UDP, raw


@pytest.fixture(autouse=True)
def native_only(pytestconfig):
    if pytestconfig.getoption("--backend") != "tap":
        pytest.skip("native TAP backend test")


def exists(name):
    return subprocess.run(['ip', 'link', 'show', name], capture_output=True).returncode == 0


def wait_interface(proc, name):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if exists(name):
            return
        if proc.poll() is not None:
            break
        time.sleep(.02)
    raise AssertionError(f"TAP {name} did not appear")


@pytest.mark.parametrize('persistent', [False, True])
@pytest.mark.parametrize('with_tx', [False, True])
def test_multiqueue_receive_and_cleanup(runtime_binary, tmp_path, persistent, with_tx):
    name = f'ffgtest{os.getpid()}'[:15]
    assert not exists(name), f"test interface already exists: {name}"
    if persistent:
        subprocess.run(['ip', 'tuntap', 'add', 'dev', name, 'mode', 'tap', 'multi_queue'], check=True)
    source = f'BACKEND: "tap"\nINTERFACE: "{name}"\nRX_THREADS: 2\n'
    if with_tx:
        source += 'PMD_THREADS: 3\nPACKET: Ether()/IP()/UDP()\n'
    path = tmp_path / 'receive.packet'
    path.write_text(source)
    proc = subprocess.Popen([str(runtime_binary), str(path), '--once' if with_tx else '--capture', '--stats-interval', '1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        wait_interface(proc, name)
        time.sleep(.1)
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as inject:
            inject.bind((name, 0))
            for port in range(40):
                inject.send(raw(Ether()/IP(src='192.0.2.1',dst='192.0.2.2')/UDP(sport=1000+port,dport=2000)))
        time.sleep(1.2)
        proc.terminate()
        out, err = proc.communicate(timeout=5)
        assert proc.returncode == 0, out + err
        import re
        counts = re.findall(r'RX worker \d+(?: lcore \d+)? queue \d+ received (\d+)', out)
        assert len(counts) == 2, out
        assert sum(map(int, counts)) >= 40, out
        assert 'port 0:' in out
        assert exists(name) == persistent
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=5)
        if persistent:
            subprocess.run(['ip', 'tuntap', 'del', 'dev', name, 'mode', 'tap', 'multi_queue'], check=True)
    assert not exists(name)


def test_sigkill_closes_nonpersistent_tap(runtime_binary, tmp_path):
    name = f'ffgkill{os.getpid()}'[:15]
    assert not exists(name)
    path = tmp_path / 'capture.packet'
    path.write_text(f'BACKEND: "tap"\nINTERFACE: "{name}"\n')
    proc = subprocess.Popen([str(runtime_binary), str(path), '--capture'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        wait_interface(proc, name)
    finally:
        proc.kill()
        proc.communicate(timeout=5)
    deadline = time.monotonic() + 2
    while exists(name) and time.monotonic() < deadline:
        time.sleep(.02)
    assert not exists(name)


def test_continuous_tx_stops_cleanly(runtime_binary, tmp_path):
    name = f'ffgloop{os.getpid()}'[:15]
    assert not exists(name)
    path = tmp_path / 'continuous.packet'
    path.write_text(f'BACKEND: "tap"\nINTERFACE: "{name}"\nPMD_THREADS: 2\nPACKET: Ether()/IP()/UDP()\n')
    proc = subprocess.Popen([str(runtime_binary), str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        wait_interface(proc, name)
        time.sleep(.2)
        proc.terminate()
        out, err = proc.communicate(timeout=5)
        assert proc.returncode == 0, out + err
        assert 'tx_errors 0' in out
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=5)
    assert not exists(name)

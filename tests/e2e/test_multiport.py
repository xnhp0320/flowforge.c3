"""Two explicit TAP ethdevs exercise discovery, worker grouping and statistics."""
from collections import Counter
import re
import select
import socket
import subprocess
import time

import pytest
from scapy.all import Ether, IP, UDP, raw


PORT_ARGS = (
    '--no-huge --no-pci -m 256 -l 0-8 '
    '--vdev=net_tap0,iface=ffg_mp0,mac=fixed '
    '--vdev=net_tap1,iface=ffg_mp1,mac=fixed'
)
PACKET = 'Ether(dst="ff:ff:ff:ff:ff:ff",src="02:64:74:61:70:00")/IP(src="[192.0.2.1-192.0.2.5]")/UDP()'


@pytest.fixture(autouse=True)
def persistent_test_taps(pytestconfig):
    if pytestconfig.getoption("--backend") != "dpdk":
        pytest.skip("DPDK multiport/lcore test")
    # Keep interface names resolvable while the capture socket drains packets
    # after --once closes its ethdevs.
    created = []
    try:
        for name in ('ffg_mp0', 'ffg_mp1'):
            subprocess.run(['ip', 'tuntap', 'add', 'dev', name, 'mode', 'tap', 'multi_queue'], check=True, capture_output=True)
            created.append(name)
            subprocess.run(['ip', 'link', 'set', name, 'up'], check=True)
        yield
    finally:
        for name in created:
            subprocess.run(['ip', 'tuntap', 'del', 'dev', name, 'mode', 'tap', 'multi_queue'], check=True)


def program(tmp_path, extra='', packet=True, args=PORT_ARGS):
    path = tmp_path / 'multi.packet'
    path.write_text(f'DPDK_ARGS: "{args}"\n{extra}\n' + (f'PACKET: {PACKET}\n' if packet else ''))
    return path


@pytest.mark.parametrize('split,workers,clones', [(True, 4, 2), (False, 4, 1), (True, None, 1)])
def test_two_ports_transmit_full_flow_set(runtime_binary, tmp_path, split, workers, clones):
    path = program(tmp_path, f'PMD_THREADS: {workers}' if workers else '')
    counts = {'ffg_mp0': Counter(), 'ffg_mp1': Counter()}
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as capture:
        capture.setblocking(False)
        proc = subprocess.Popen([str(runtime_binary), str(path), '--once', '--clone', str(clones)] + (['--split'] if split else []), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 10
        try:
            while time.monotonic() < deadline:
                if select.select([capture], [], [], 0.15)[0]:
                    data, addr = capture.recvfrom(65535)
                    pkt = Ether(data)
                    if addr[0] in counts and pkt.src == '02:64:74:61:70:00' and IP in pkt:
                        counts[addr[0]][pkt[IP].src] += 1
                elif proc.poll() is not None:
                    break
            out, err = proc.communicate(timeout=2)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
    assert proc.returncode == 0, out + err
    copies = clones if split else (workers or 2) // 2 * clones
    expected = Counter({f'192.0.2.{i}': copies for i in range(1, 6)})
    assert counts == {'ffg_mp0': expected, 'ffg_mp1': expected}, out + err
    assert 'Port 0:' in out and 'Port 1:' in out
    assert f'planned_transmissions_per_cycle {10 * copies}' in out
    groups = out.split('Port ')[1:]
    assert len(groups) == 2
    for group in groups:
        queues = re.findall(r'PMD worker \d+ lcore \d+ queue (\d+)', group)
        assert queues == [str(i) for i in range((workers or 2) // 2)]


@pytest.mark.parametrize('extra,options,message', [
    ('PMD_THREADS: 3', ['--once'], 'must each be divisible'),
    ('PMD_THREADS: 2\nRX_THREADS: 1', ['--once'], 'must each be divisible'),
    ('', ['--capture', 'OUTPUT'], 'PCAP capture supports only one'),
])
def test_multiport_rejects_invalid_configuration(runtime_binary, tmp_path, extra, options, message):
    output = tmp_path / 'capture.pcap'
    options = [str(output) if x == 'OUTPUT' else x for x in options]
    path = program(tmp_path, extra)
    result = subprocess.run([str(runtime_binary), str(path), *options], capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert message in result.stdout + result.stderr
    assert not output.exists()


@pytest.mark.parametrize('with_tx', [False, True])
def test_two_ports_capture_groups_and_live_stats(runtime_binary, tmp_path, with_tx):
    path = program(tmp_path, 'PMD_THREADS: 4\nRX_THREADS: 4' if with_tx else '', packet=with_tx)
    proc = subprocess.Popen([str(runtime_binary), str(path), '--once' if with_tx else '--capture', '--stats-interval', '1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if all(subprocess.run(['ip', 'link', 'show', name], capture_output=True).returncode == 0 for name in ('ffg_mp0', 'ffg_mp1')):
                break
            if proc.poll() is not None:
                break
            time.sleep(.1)
        time.sleep(.5)
        assert subprocess.run(['ip', 'link', 'show', 'packet_tap0'], capture_output=True).returncode != 0
        for i, name in enumerate(('ffg_mp0', 'ffg_mp1')):
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as inject:
                inject.bind((name, 0))
                data = raw(Ether(dst='ff:ff:ff:ff:ff:ff') / IP(src='192.0.2.100') / UDP() / (b'x' * (20 + i * 20)))
                for _ in range(3 + i):
                    inject.send(data)
        time.sleep(1.5)
    finally:
        proc.terminate()
        try:
            out, err = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
    assert proc.returncode == 0, out + err
    assert 'port 0:' in out and 'port 1:' in out and 'overall rx total:' in out
    rows = re.findall(r'Port (\d+): TX \d+/\d+ RX (\d+) bytes (\d+)', out)
    assert len(rows) == 2, out
    assert int(rows[0][1]) >= 3 and int(rows[1][1]) >= 4
    assert 'RX worker 0' in out and 'RX worker 1' in out


def test_multiport_requires_enough_worker_lcores(runtime_binary, tmp_path):
    path = program(tmp_path, args=PORT_ARGS.replace('-l 0-8', '-l 0-1'))
    result = subprocess.run([str(runtime_binary), str(path), '--once'], capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert 'requires 2 worker lcore(s)' in result.stdout + result.stderr

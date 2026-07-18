import os
import platform
import select
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.all import Ether  # noqa: E402
from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS, ICMPv6ND_RA  # noqa: E402


TAP_IFACE = "packet_tap0"
DEFAULT_DPDK_ARGS = "--no-huge --no-pci -l 0-1"
ETH_P_ALL = 0x0003
RUNTIME_SRC_MAC = "02:64:74:61:70:00"


@dataclass
class RuntimeCapture:
    packets: list
    stdout: str
    stderr: str


def pytest_addoption(parser):
    parser.addoption(
        "--runtime",
        default=os.environ.get("FFG_RUNTIME") or os.environ.get("PACKET_TAP_RUNTIME"),
        help="Path to the ffg runtime binary.",
    )


@pytest.fixture(scope="session")
def runtime_binary(pytestconfig):
    runtime = pytestconfig.getoption("--runtime")
    if not runtime:
        pytest.skip("ffg runtime path was not provided")
    path = Path(runtime)
    if not path.exists():
        pytest.skip(f"ffg runtime does not exist: {path}")
    return path


@pytest.fixture(autouse=True)
def require_tap_host(runtime_binary):
    if platform.system() != "Linux":
        pytest.skip("DPDK tap e2e tests require Linux")
    if not Path("/dev/net/tun").exists():
        pytest.skip("/dev/net/tun is not available")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        pytest.skip("DPDK tap e2e tests require root or equivalent network capabilities")


@pytest.fixture
def packet_program(tmp_path):
    def write_program(
        packet: str,
        *,
        packet_count: Optional[int] = None,
        dpdk_args: str = DEFAULT_DPDK_ARGS,
        pmd_threads: Optional[int] = None,
        tx_batch_size: Optional[int] = None,
    ) -> Path:
        lines = [f'DPDK_ARGS: "{dpdk_args}"']
        if packet_count is not None:
            lines.append(f"PACKET_COUNT: {packet_count}")
        if pmd_threads is not None:
            lines.append(f"PMD_THREADS: {pmd_threads}")
        if tx_batch_size is not None:
            lines.append(f"TX_BATCH_SIZE: {tx_batch_size}")
        lines.append(f"PACKET: {packet}")
        program = tmp_path / "traffic.packet"
        program.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return program

    return write_program


def permission_error(output: str) -> bool:
    markers = [
        "/dev/net/tun",
        "TUNSETIFF",
        "Operation not permitted",
        "Permission denied",
        "failed to create TAP",
    ]
    return any(marker in output for marker in markers)


def is_runtime_packet(packet) -> bool:
    if Ether not in packet or packet.src != RUNTIME_SRC_MAC:
        return False
    if packet.type == 0x0800:
        return True
    if packet.type == 0x86dd:
        for nd in (ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RS, ICMPv6ND_RA):
            if nd in packet:
                return False
        return True
    return False


def capture_runtime_packets(
    capture: socket.socket,
    expected_count: int,
    timeout: float,
    process: Optional[subprocess.Popen] = None,
):
    packets = []
    deadline = time.monotonic() + timeout
    while len(packets) < expected_count and time.monotonic() < deadline:
        wait = min(0.1, max(0.0, deadline - time.monotonic()))
        readable, _, _ = select.select([capture], [], [], wait)
        if readable:
            data, _ = capture.recvfrom(65535)
            packet = Ether(data)
            if is_runtime_packet(packet):
                packets.append(packet)

        if process is not None and process.poll() is not None:
            break

    return packets


@pytest.fixture
def capture_packets(runtime_binary):
    def run(
        program: Path,
        expected_count: int,
        *,
        timeout: float = 8.0,
        with_output: bool = False,
        runtime_args: Optional[list] = None,
    ):
        args = [str(runtime_binary), str(program), "--once"]
        if runtime_args:
            args.extend(runtime_args)
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)) as capture:
            capture.setblocking(False)
            process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            packets = capture_runtime_packets(capture, expected_count, timeout, process=process)

        try:
            stdout, stderr = process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            pytest.fail(f"runtime timed out\nstdout:\n{stdout}\nstderr:\n{stderr}")

        output = stdout + stderr
        if process.returncode != 0:
            if permission_error(output):
                pytest.skip(output.strip())
            pytest.fail(f"runtime failed with exit code {process.returncode}\n{output}")
        if len(packets) != expected_count:
            pytest.fail(
                f"captured {len(packets)} packet(s), expected {expected_count}\n"
                f"stdout:\n{stdout}\nstderr:\n{stderr}"
            )
        if with_output:
            return RuntimeCapture(packets=packets, stdout=stdout, stderr=stderr)
        return packets

    return run


@dataclass
class CaptureResult:
    packets: list
    stdout: str
    stderr: str


@pytest.fixture
def run_capture_mode(runtime_binary, tmp_path):
    def run(
        *,
        dpdk_args: str = DEFAULT_DPDK_ARGS,
        capture_file: Optional[Path] = None,
        injector,
        timeout: float = 8.0,
    ):
        lines = [f'DPDK_ARGS: "{dpdk_args}"']
        program = tmp_path / "capture.packet"
        program.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # The C3 ffg CLI takes the capture file positionally after --capture.
        args = [str(runtime_binary), str(program), "--capture"]
        if capture_file:
            args.append(str(capture_file))

        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            # Poll for DPDK to create the TAP interface
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                iface_check = subprocess.run(["ip", "link", "show", TAP_IFACE], capture_output=True)
                if iface_check.returncode == 0:
                    break
                time.sleep(0.2)
            else:
                pytest.fail(f"TAP interface {TAP_IFACE} did not appear within 10s")

            time.sleep(0.5)
            injector()
            time.sleep(0.5)
            process.terminate()
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            pytest.fail(f"capture mode timed out\nstdout:\n{stdout}\nstderr:\n{stderr}")

        output = stdout + stderr
        if process.returncode != 0:
            if permission_error(output):
                pytest.skip(output.strip())
            pytest.fail(f"capture mode failed with exit code {process.returncode}\n{output}")

        packets = []
        if capture_file and capture_file.exists():
            try:
                from scapy.all import rdpcap
                packets = rdpcap(str(capture_file))
            except Exception as exc:
                pytest.fail(f"failed to read pcap: {exc}")

        return CaptureResult(packets=packets, stdout=stdout, stderr=stderr)

    return run

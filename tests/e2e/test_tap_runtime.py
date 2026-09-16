from collections import Counter
import re
import socket

import pytest
from scapy.all import ICMP, ICMPv6EchoRequest, IP, IPv6, TCP, UDP, raw
from scapy.layers.inet import in4_chksum
from scapy.layers.inet6 import in6_chksum
from scapy.layers.vxlan import VXLAN
from scapy.utils import checksum


ETHER = 'Ether(dst="ff:ff:ff:ff:ff:ff",src="02:64:74:61:70:00")'
TAP_IFACE = "packet_tap0"
WORKER_RE = re.compile(
    r"(?:PMD|TX) worker (\d+)(?: lcore (\d+))? queue (\d+) flows (\d+)\+(\d+) sent (\d+)/(\d+) packet\(s\)"
)


def assert_ipv4_tcp_checksums(packet):
    ip = packet[IP]
    assert checksum(raw(ip)[: ip.ihl * 4]) == 0
    assert in4_chksum(socket.IPPROTO_TCP, ip, raw(packet[TCP])) == 0


def assert_ipv6_tcp_checksum(packet):
    assert in6_chksum(socket.IPPROTO_TCP, packet[IPv6], raw(packet[TCP])) == 0


@pytest.mark.parametrize(
    ("packet", "layer", "checks"),
    [
        (
            f'{ETHER}/IP(src="192.0.2.1",dst="192.0.2.2")/TCP(sport=1234,dport=80,flags=2)',
            TCP,
            {"sport": 1234, "dport": 80},
        ),
        (
            f'{ETHER}/IP(src="192.0.2.3",dst="192.0.2.4")/UDP(sport=1235,dport=53)',
            UDP,
            {"sport": 1235, "dport": 53},
        ),
        (
            f'{ETHER}/IP(src="192.0.2.5",dst="192.0.2.6")/ICMP(type=8,code=0,id=7,seq=9)',
            ICMP,
            {"type": 8, "code": 0, "id": 7, "seq": 9},
        ),
    ],
)
def test_generates_normal_ipv4_l4_packets(packet_program, capture_packets, packet, layer, checks):
    packets = capture_packets(packet_program(packet, packet_count=1), 1)

    assert IP in packets[0]
    assert layer in packets[0]
    for field, value in checks.items():
        assert getattr(packets[0][layer], field) == value


@pytest.mark.parametrize(
    ("packet", "layer", "checks"),
    [
        (
            f'{ETHER}/IPv6(src="2001:db8::1",dst="2001:db8::2")/TCP(sport=1234,dport=80,flags=2)',
            TCP,
            {"sport": 1234, "dport": 80},
        ),
        (
            f'{ETHER}/IPv6(src="2001:db8::3",dst="2001:db8::4")/UDP(sport=1235,dport=53)',
            UDP,
            {"sport": 1235, "dport": 53},
        ),
        (
            f'{ETHER}/IPv6(src="2001:db8::5",dst="2001:db8::6")/ICMP(type=128,code=0,id=7,seq=9)',
            ICMPv6EchoRequest,
            {"type": 128, "code": 0, "id": 7, "seq": 9},
        ),
    ],
)
def test_generates_normal_ipv6_l4_packets(packet_program, capture_packets, packet, layer, checks):
    packets = capture_packets(packet_program(packet, packet_count=1), 1)

    assert IPv6 in packets[0]
    assert layer in packets[0]
    for field, value in checks.items():
        assert getattr(packets[0][layer], field) == value


def test_generates_ipv4_and_tcp_options(packet_program, capture_packets):
    program = packet_program(
        f'{ETHER}/IP(src="198.51.100.1",dst="198.51.100.2",'
        'options=IPOption_NOP()/IPOption_EOL())/'
        'TCP(sport=1234,dport=443,flags=2,options=TCPOption_MSS(value=1460))',
        packet_count=1,
    )

    packet = capture_packets(program, 1)[0]

    assert packet[IP].ihl == 6
    assert packet[TCP].dataofs == 6
    assert ("MSS", 1460) in packet[TCP].options


@pytest.mark.parametrize(
    ("inner_l4", "layer", "checks"),
    [
        ('TCP(sport=2000,dport=2001,flags=2)', TCP, {"sport": 2000, "dport": 2001}),
        ('UDP(sport=3000,dport=3001)', UDP, {"sport": 3000, "dport": 3001}),
        ('ICMP(type=8,code=0,id=10,seq=11)', ICMP, {"type": 8, "code": 0, "id": 10, "seq": 11}),
    ],
)
def test_generates_vxlan_encapsulated_ipv4_packets(packet_program, capture_packets, inner_l4, layer, checks):
    program = packet_program(
        f'{ETHER}/IP(src="203.0.113.1",dst="203.0.113.2")/UDP()/VXLAN(vni=42)/'
        f'Ether(dst="02:00:00:00:00:02",src="02:00:00:00:00:01")/'
        f'IP(src="10.10.0.1",dst="10.10.0.2")/{inner_l4}',
        packet_count=1,
    )

    packet = capture_packets(program, 1)[0]
    inner = packet[VXLAN].payload

    assert VXLAN in packet
    assert packet[VXLAN].vni == 42
    assert IP in inner
    assert layer in inner
    for field, value in checks.items():
        assert getattr(inner[layer], field) == value


def test_generates_cartesian_ipv4_and_tcp_port_ranges(packet_program, capture_packets):
    program = packet_program(
        f'{ETHER}/IP(src="[10.0.0.1-10.0.0.4]",dst="10.0.1.1")/'
        'TCP(sport="[10000-10002]",dport=443,flags=2)',
        packet_count=12,
    )

    packets = capture_packets(program, 12)
    flows = {(packet[IP].src, packet[TCP].sport) for packet in packets}

    assert flows == {
        (ip, port)
        for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
        for port in [10000, 10001, 10002]
    }


def test_generates_cartesian_ipv6_and_tcp_port_ranges(packet_program, capture_packets):
    program = packet_program(
        f'{ETHER}/IPv6(src="[2001:db8::1-2001:db8::4]",dst="2001:db8::ff")/'
        'TCP(sport="[10000-10002]",dport=443,flags=2)',
        packet_count=12,
    )

    packets = capture_packets(program, 12)
    flows = {(packet[IPv6].src, packet[TCP].sport) for packet in packets}

    assert flows == {
        (ip, port)
        for ip in ["2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4"]
        for port in [10000, 10001, 10002]
    }


def test_generates_stepped_ipv4_and_tcp_port_ranges(packet_program, capture_packets):
    program = packet_program(
        f'{ETHER}/IP(src="10.0.0.1-10.0.0.6(step=2)",dst="10.0.1.1")/'
        'TCP(sport="100-103(step=2)",dport=443,flags=2)',
        packet_count=24,
    )

    packets = capture_packets(program, 24)
    assert {(packet[IP].src, packet[TCP].sport) for packet in packets} == {
        (f"10.0.0.{last}", sport)
        for last in range(1, 7)
        for sport in range(100, 104)
    }
    for packet in packets:
        assert_ipv4_tcp_checksums(packet)


def test_generates_stepped_ipv6_and_tcp_port_ranges(packet_program, capture_packets):
    program = packet_program(
        f'{ETHER}/IPv6(src="2001:db8::1-2001:db8::6(step=2)",dst="2001:db8::ff")/'
        'TCP(sport="200-203(step=2)",dport=443,flags=2)',
        packet_count=24,
    )

    packets = capture_packets(program, 24)
    assert {(packet[IPv6].src, packet[TCP].sport) for packet in packets} == {
        (f"2001:db8::{last:x}", sport)
        for last in range(1, 7)
        for sport in range(200, 204)
    }
    for packet in packets:
        assert_ipv6_tcp_checksum(packet)


def test_each_range_list_entry_uses_its_own_step(packet_program, capture_packets):
    program = packet_program(
        f'{ETHER}/IP(src="192.0.2.1",dst="192.0.2.2")/'
        'TCP(sport="[1-5(step=2),10-12(step=100)]",dport=443,flags=2)',
        packet_count=8,
    )

    packets = capture_packets(program, 8)
    assert {packet[TCP].sport for packet in packets} == {1, 2, 3, 4, 5, 10, 11, 12}
    for packet in packets:
        assert_ipv4_tcp_checksums(packet)


def assert_random_samples(values, allowed, minimum_distinct):
    counts = Counter(values)
    assert set(counts) <= set(allowed), counts
    assert len(counts) >= minimum_distinct, counts

    # This is deliberately a broad smoke-test bound, not a PRNG quality test.
    # It catches a stuck or severely biased generator while keeping the chance
    # of rejecting a healthy uniform generator negligible.
    expected = len(values) / len(allowed)
    chi_square = sum((counts[value] - expected) ** 2 / expected for value in allowed)
    assert chi_square < 80, counts


def test_generates_random_ipv4_and_tcp_port_ranges(packet_program, capture_packets):
    addresses = [f"198.51.100.{last}" for last in range(1, 17)]
    ports = list(range(20000, 20016))
    program = packet_program(
        f'{ETHER}/IP(src="198.51.100.1-198.51.100.16(rand)",dst="198.51.100.254")/'
        'TCP(sport="20000-20015(rand)",dport=443,flags=2)',
        packet_count=48,
        tx_batch_size=64,
    )

    packets = capture_packets(program, 48)
    assert_random_samples([packet[IP].src for packet in packets], addresses, 10)
    assert_random_samples([packet[TCP].sport for packet in packets], ports, 10)
    for packet in packets:
        assert_ipv4_tcp_checksums(packet)


def test_generates_random_ipv6_and_tcp_port_ranges(packet_program, capture_packets):
    addresses = [f"2001:db8::{last:x}" for last in range(1, 17)]
    ports = list(range(30000, 30016))
    program = packet_program(
        f'{ETHER}/IPv6(src="2001:db8::1-2001:db8::10(rand)",dst="2001:db8::ff")/'
        'TCP(sport="30000-30015(rand)",dport=443,flags=2)',
        packet_count=48,
        tx_batch_size=64,
    )

    packets = capture_packets(program, 48)
    assert_random_samples([packet[IPv6].src for packet in packets], addresses, 10)
    assert_random_samples([packet[TCP].sport for packet in packets], ports, 10)
    for packet in packets:
        assert_ipv6_tcp_checksum(packet)


def test_generates_stepped_range_with_large_payload(packet_program, capture_packets):
    program = packet_program(
        f'{ETHER}/IP(src="198.51.100.1-198.51.100.8(step=2)",dst="198.51.100.100")/'
        'TCP(sport="300-307(step=2)",dport=443,flags=2)/Payload(length=1200)',
        packet_count=4,
    )

    result = capture_packets(program, 4, with_output=True)
    assert {(packet[IP].src, packet[TCP].sport) for packet in result.packets} == {
        ("198.51.100.1", 300),
        ("198.51.100.3", 300),
        ("198.51.100.5", 300),
        ("198.51.100.7", 300),
    }
    if "runtime completed" in result.stdout:
        assert "packet_len 1254 bytes" in result.stdout
        assert "tx_errors 0" in result.stdout
    for packet in result.packets:
        assert len(packet) == 1254
        assert len(bytes(packet[TCP].payload)) == 1200
        assert_ipv4_tcp_checksums(packet)


def test_clone_repeats_each_flow_before_advancing(packet_program, capture_packets):
    program = packet_program(
        f'{ETHER}/IP(src="[10.0.0.1-10.0.0.2]",dst="10.0.1.1")/'
        'TCP(sport=10000,dport=443,flags=2)',
        packet_count=2,
    )

    result = capture_packets(program, 4, with_output=True, runtime_args=["--clone", "2"])
    flows = [(packet[IP].src, packet[TCP].sport) for packet in result.packets]

    assert flows == [
        ("10.0.0.1", 10000),
        ("10.0.0.1", 10000),
        ("10.0.0.2", 10000),
        ("10.0.0.2", 10000),
    ]
    assert "clone_count 2" in result.stdout


def test_multi_pmd_workers_emit_duplicate_cartesian_ranges(packet_program, capture_packets):
    program = packet_program(
        f'{ETHER}/IP(src="[10.0.0.1-10.0.0.2]",dst="10.0.1.1")/'
        'TCP(sport="[10000-10001]",dport=443,flags=2)',
        packet_count=4,
        dpdk_args="--no-huge --no-pci -m 256 -l 0-2",
        pmd_threads=2,
        tx_batch_size=4,
    )

    result = capture_packets(program, 8, with_output=True)
    flows = Counter((packet[IP].src, packet[TCP].sport) for packet in result.packets)
    expected_flows = {
        (ip, port)
        for ip in ["10.0.0.1", "10.0.0.2"]
        for port in [10000, 10001]
    }

    assert set(flows) == expected_flows
    assert all(count == 2 for count in flows.values())
    assert "pmd_threads 2" in result.stdout
    assert "tx_batch_size 4" in result.stdout
    assert "once on" in result.stdout

    workers = [
        {
            "worker": int(match.group(1)),
            "lcore": int(match.group(2)) if match.group(2) else None,
            "queue": int(match.group(3)),
            "first_flow": int(match.group(4)),
            "flow_count": int(match.group(5)),
            "sent": int(match.group(6)),
            "attempted": int(match.group(7)),
        }
        for match in WORKER_RE.finditer(result.stdout)
    ]
    assert len(workers) == 2
    assert {worker["worker"] for worker in workers} == {0, 1}
    assert {worker["queue"] for worker in workers} == {0, 1}
    assert all(worker["first_flow"] == 0 and worker["flow_count"] == 4 for worker in workers)
    assert all(worker["sent"] == 4 and worker["attempted"] == 4 for worker in workers)


def test_split_pmd_workers_partition_cartesian_ranges(packet_program, capture_packets):
    program = packet_program(
        f'{ETHER}/IP(src="[10.0.0.1-10.0.0.3]",dst="10.0.1.1")/'
        'TCP(sport="[10000-10001]",dport=443,flags=2)',
        packet_count=5,
        dpdk_args="--no-huge --no-pci -m 256 -l 0-2",
        pmd_threads=2,
        tx_batch_size=4,
    )

    result = capture_packets(program, 5, with_output=True, runtime_args=["--split"])
    flows = Counter((packet[IP].src, packet[TCP].sport) for packet in result.packets)
    expected_flows = {
        ("10.0.0.1", 10000),
        ("10.0.0.2", 10000),
        ("10.0.0.3", 10000),
        ("10.0.0.1", 10001),
        ("10.0.0.2", 10001),
    }

    assert set(flows) == expected_flows
    assert all(count == 1 for count in flows.values())
    assert "split on" in result.stdout

    workers = [
        {
            "worker": int(match.group(1)),
            "queue": int(match.group(3)),
            "first_flow": int(match.group(4)),
            "flow_count": int(match.group(5)),
            "sent": int(match.group(6)),
            "attempted": int(match.group(7)),
        }
        for match in WORKER_RE.finditer(result.stdout)
    ]
    assert len(workers) == 2
    assert workers[0]["first_flow"] == 0
    assert workers[0]["flow_count"] == 3
    assert workers[1]["first_flow"] == 3
    assert workers[1]["flow_count"] == 2
    assert [worker["sent"] for worker in workers] == [3, 2]
    assert [worker["attempted"] for worker in workers] == [3, 2]


@pytest.fixture
def inject_udp_packet():
    def send(count: int = 1):
        import socket
        from scapy.all import raw, IP, UDP, Ether
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="02:00:00:00:00:01") / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1234, dport=5678)
        data = raw(pkt)
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
            sock.bind((TAP_IFACE, 0))
            for _ in range(count):
                sock.send(data)
    return send


def test_capture_stats(run_capture_mode, inject_udp_packet):
    def inject():
        inject_udp_packet(count=3)

    result = run_capture_mode(injector=inject)
    assert "Capture completed" in result.stdout
    # Parse rx_received from stdout, e.g. "received 3 bytes ..."
    import re
    match = re.search(r"received (\d+)", result.stdout)
    assert match is not None
    rx_received = int(match.group(1))
    assert rx_received >= 3


def test_capture_to_pcap(run_capture_mode, inject_udp_packet, tmp_path):
    cap_file = tmp_path / "capture.pcap"

    def inject():
        inject_udp_packet(count=5)

    result = run_capture_mode(capture_file=cap_file, injector=inject)
    # Filter for our injected UDP packets (kernel may generate ARP/NDP too)
    udp_packets = [pkt for pkt in result.packets if pkt.haslayer(UDP)]
    assert len(udp_packets) == 5
    for pkt in udp_packets:
        assert pkt.haslayer(IP)
        assert pkt[IP].src == "10.0.0.1"
        assert pkt[IP].dst == "10.0.0.2"
        assert pkt[UDP].sport == 1234
        assert pkt[UDP].dport == 5678

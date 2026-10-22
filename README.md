# FlowForge (C3)

FlowForge is a packet DSL and traffic generator written in C3, ported from the
C++ FlowForge project. It uses Scapy-like expressions to describe packet stacks,
expand field ranges into flows, and generate PCAP files or transmit live traffic.

The packet pipeline parses and validates expressions, constructs and serializes
packets, then applies per-flow field updates and length/checksum fixups.

## Features

- Packet composition with Ethernet, VLAN, IPv4/IPv6, TCP, UDP, ICMP, VXLAN,
  IP/TCP options, and payloads.
- Integer and IP address ranges, cartesian flow expansion, stepped traversal,
  and random value selection.
- Custom header definitions loaded with `--headers <file>`.
- PCAP output without network devices or DPDK dependencies.
- Linux native TAP and optional DPDK backends for live TX/RX, capture,
  multiple workers, clone/split modes, and interval statistics.
- Software checksum fixups and DPDK checksum offload support.

## Build

Requires C3 0.8.4 and a C compiler. The default target builds on macOS and Linux
without DPDK.

```sh
c3c build
c3c test
```

The executable is `build/ffg`. The optional Linux DPDK target uses the
`/opt/dpdk` installation paths configured in `project.json`:

```sh
c3c build ffg-dpdk
c3c test ffg-dpdk
```

`project.e2.json` provides the XSL-specific build configuration.

## Usage

Validate a packet program or inspect an inline expression:

```sh
./build/ffg --check examples/native_tap.packet
./build/ffg -e 'Ether()/IP(src="192.0.2.1")/TCP(dport=443)'
```

Write packets to a PCAP file. Ranges expand into a cartesian product; `-c` caps
how many packets are written:

```sh
./build/ffg -w out.pcap -c 12 -e 'Ether()/IP(src="192.0.2.1-192.0.2.4")/TCP(sport="10000-10002",dport=443)'
```

Packet programs use named variables and a `PACKET` expression. Select the live
backend in the program itself:

```text
BACKEND: "tap"
INTERFACE: "packet_tap0"
PACKET_COUNT: 4
PACKET: Ether()/IP(src="192.0.2.1-192.0.2.4")/UDP(sport=1234,dport=5678)
```

Run the native TAP example on Linux with root or `CAP_NET_ADMIN` and access to
`/dev/net/tun`:

```sh
sudo ./build/ffg examples/native_tap.packet --once
sudo ./build/ffg examples/native_tap.packet --clone 4 --stats-interval 2
sudo ./build/ffg examples/native_tap.packet --capture out.pcap
```

`--check` validates configuration without opening devices or initializing DPDK.
For DPDK live traffic, use `build/ffg-dpdk` and
[examples/tap_runtime.packet](examples/tap_runtime.packet). Native TAP uses
software checksums and serves as a functional test backend.

## Project structure

| Path | Contents |
| --- | --- |
| `src/` | C3 packet pipeline, protocol registry, CLI, and live runtimes |
| `csrc/` | Native TAP helpers and DPDK C ABI shim |
| `test/` | C3 unit tests |
| `tests/cli/` | Python CLI tests |
| `tests/e2e/` | Packet verification through PCAP, native TAP, and DPDK |
| `examples/` | Native TAP, DPDK TAP, and XSL packet programs |
| `scripts/` | Linux and Lima test runners |
| `docs/` | Local environment and testing instructions |

## Testing

Run unit tests and PCAP-based checks locally, including on macOS:

```sh
c3c test
python3 -m pip install -r tests/requirements.txt
python3 -m pytest tests/cli tests/e2e --backend pcap --runtime "$PWD/build/ffg" -q
```

Live TAP tests require Linux, root, and `/dev/net/tun`:

```sh
sudo python3 -m pytest tests/e2e --backend tap --runtime "$PWD/build/ffg" -v
```

From macOS, `sh scripts/test-lima.sh` runs the Linux suite in Lima.
See [local testing](docs/local-testing.md) for toolchain setup, isolated builds,
and DPDK validation details.

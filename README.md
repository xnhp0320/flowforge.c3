# FlowForge (C3)

C3 port of [FlowForge](../packet_editor) — a Scapy-like packet DSL for DPDK traffic generation.

## Phase 1

DPDK-free pipeline using **C3 stdlib only** (no vendor bindings):

```
Lexer → Parser → Checker
```

- Parses `.packet` program files and inline packet expressions
- Validates headers and attributes against a built-in protocol registry
- Unit tests mirror the original C++ lexer/parser/checker suite (**98** cases)

## Phase 2

Constructor stage, porting `PacketConstructorBuilder` from the C++
`packet_editor`:

```
Lexer → Parser → Checker → Constructor
```

- `src/value.c3` / `src/cvalue.c3` — `MacAddr`/`IPv4`/`IPv6` value types and
  scalar/range/bit-field parsing helpers used to build `ConstructorValue`s
- `src/registry.c3` — extended with `FieldSpec`/`OptionSpec`/`HeaderSpec`
  bit-layout metadata and parent→child inference rules (e.g. Ether/VLAN type,
  IP/IPv6 next-protocol)
- `src/constructor.c3` — builds a `PacketConstructor` (defaults, explicit
  attribute values, duplicate/unknown attribute detection, nested
  packet-valued options, IP/TCP option length fields, `Payload`
  `length`/`total_length`, and inference-rule propagation)

## Phase 3

Serializer stage, porting `packet_serializer` from the C++ `packet_editor`:

```
Lexer → Parser → Checker → Constructor → Serializer
```

- `src/serializer.c3` —
  - `serialize_packet()` writes a `PacketConstructor` into a byte buffer
    (bit/byte field writers, IP/TCP option-packet nesting, `Payload` length
    extension) and returns `PayloadFieldModifier`s that record range-valued
    fields (IPv4/IPv6/integer ranges) so later flow-expansion code can index
    into the range list and patch a specific value into the payload.
  - `plan_packet_fixups()` / `fixup_packet()` compute and apply IPv4/IPv6/
    TCP/UDP/ICMP length and checksum fixups, with a `FixupMode` of
    `SOFTWARE`, `HARDWARE_OFFLOAD`, or `DISABLED` per protocol; hardware
    offload mode records a `PacketOffloadRequest` (layer lengths + which
    checksums to offload) instead of computing the checksum in software.

## Phase 4

File mode — DPDK-free packet generation and pcap output, porting
`packet_generator` and `pcap_writer` from the C++ `packet_editor`:

```
Lexer → Parser → Checker → Constructor → Serializer → Generator → Pcap
```

- `src/generator.c3` — `PacketGenerator.prepare()` runs
  check → construct → serialize → fixup once to build a `GeneratedPacket`
  (base payload, range modifiers, fixup plan) and plans the total flow
  count from the range fields (capped by an optional packet count).
  `payload_for_flow()` / `apply_flow()` then patch a specific flow index
  into a payload buffer (indexing each range modifier and re-running the
  fixup plan), so millions of flows expand without re-serializing.
- `src/pcap.c3` — `PcapWriter` appends a classic little-endian pcap
  header and per-packet records (Ethernet link type) to a byte buffer.
- `src/main.c3` — the `ffg` CLI wires file mode together: `-w <out.pcap>`
  expands a program/expression into flows and writes them to a pcap
  (`-c <count>` caps the expansion).
- Unit tests mirror the C++ `test_file_mode` suite (**5** cases).

## Phase 5

Live DPDK runtime, porting `packet::Runtime` from the C++ `packet_editor`:

```
Lexer → Parser → Checker → Constructor → Serializer → Generator → DPDK EAL → TX/RX
```

- `src/runtime.c3` — the DPDK-free **check** path (`Runtime.check`,
  `build_config`, `split_dpdk_args`, flow/clone/worker transmission counting).
  This stays free of any DPDK call so the 26 check-only tests run without an EAL.
- `csrc/dpdk_shim.c` / `csrc/dpdk_shim.h` — a small C shim that is the *only*
  translation unit including DPDK headers. It exposes the macros, thread-local
  variables and `static inline` helpers (mbuf field access, `RTE_MBUF_F_TX_*`
  flags, `rte_pktmbuf_*`, `rte_eth_tx/rx_burst`, lcore enumeration, the checksum
  offload request, and a Linux `/dev/net/tun` TAP preflight) behind plain
  C-ABI `ff_*` functions.
- `src/dpdk.c3` (`flowforge::dpdk`) — thin `extern fn` bindings: the exported
  `rte_*` symbols are bound directly, everything else via the `ff_*` shim.
- `src/runtime_live.c3` — the EAL-backed pipeline mirroring `Runtime::run`:
  TAP preflight → `rte_eal_init` → mbuf pool seeded from the generated base
  payload → TAP vdev probe (`net_tap0`, `iface=packet_tap0`) → port
  configure/start → `run_traffic` with TX/RX workers on worker lcores. When
  `DPDK_ARGS` provides no worker lcore (e.g. `-l 0`) the single TX worker runs
  on the **main lcore** so single-core setups still transmit. Hardware checksum
  offload is applied per mbuf via `apply_dpdk_offload`. A `--capture` path
  (Slice D) receives on the TAP port and optionally writes a pcap via the
  existing `PcapWriter`.
- DPDK lives at **`/opt/dpdk`** (`include/`, `lib/x86_64-linux-gnu/`,
  `PKG_CONFIG_PATH=/opt/dpdk/lib/x86_64-linux-gnu/pkgconfig`). `project.json`
  wires the C shim (`c-sources`, `c-include-dirs`, `cflags` with
  `-include rte_config.h`), the DPDK shared libraries + TAP/vdev/mempool_ring
  drivers, and `-Wl,-rpath,/opt/dpdk/lib/x86_64-linux-gnu`.
- A unit test (`test/runtime_dpdk_test.c3`) links DPDK and checks
  `apply_dpdk_offload` mbuf metadata (mirrors
  `RuntimeTest.AppliesDpdkOffloadRequestToMbufMetadata`).
- **e2e transmit/capture needs root and TAP access** (`CAP_NET_ADMIN`,
  `/dev/net/tun`); the check path and the offload test run without privileges.

## Build

Requires [c3c](https://github.com/c3lang/c3c) 0.8+ and DPDK at `/opt/dpdk`.

```bash
export PKG_CONFIG_PATH=/opt/dpdk/lib/x86_64-linux-gnu/pkgconfig
c3c build
c3c test
c3c run -- --check examples/tap_runtime.packet
```

### Live mode (needs root)

```bash
# Validate a runtime program without touching the EAL:
./build/ffg --check examples/tap_runtime.packet

# Transmit one full pass over the flows on the TAP port:
sudo ./build/ffg examples/tap_runtime.packet --once

# Transmit continuously, cloning each flow 4x, with a live stats view:
sudo ./build/ffg examples/tap_runtime.packet --clone 4 --stats-interval 2

# Capture from the TAP port to a pcap (Ctrl-C to stop):
sudo ./build/ffg examples/tap_runtime.packet --capture out.pcap
```

Live flags: `--clone <n>`, `--split`, `--once`, `--stats-interval <sec>`,
`--capture [<out.pcap>]`. A program is treated as a live runtime program when it
declares a `DPDK_ARGS` variable; `--check` forces the DPDK-free check instead.

### End-to-end TAP tests (needs root)

A `pytest`/`scapy` suite in `tests/e2e/` drives the built `ffg` over a DPDK TAP
port and verifies the packets that reach the wire (normal L4, IP/TCP options,
VXLAN encapsulation, cartesian ranges, `--clone`/`--split` worker partitioning,
and `--capture`). It requires root, `/dev/net/tun`, `pytest`, and `scapy`.

```bash
pip install pytest scapy
c3c build
sudo FFG_RUNTIME=$PWD/build/ffg python3 -m pytest tests/e2e/ -v
```

## CLI

```bash
./build/ffg examples/tap_runtime.packet          # parse + check program
./build/ffg -e 'Ether()/IP(src="10.0.0.1")/TCP(dport=80)'
./build/ffg --parse-only examples/tap_runtime.packet   # syntax only, no registry check
```

### File mode (write a pcap)

Expands range fields into flows and writes the packets to a pcap file
(checksums/lengths are fixed up per flow):

```bash
# From a program file (uses its PACKET_COUNT: when present)
./build/ffg -w out.pcap examples/tap_runtime.packet

# From an inline expression, capping the range expansion at 12 flows
./build/ffg -w out.pcap -c 12 -e 'Ether()/IP(src="[10.0.0.1-10.0.0.4]")/TCP(sport="[10000-10002]",dport=443)'
```

`-w`/`--write <file>` selects file mode; `-c`/`--count <n>` caps the number
of generated packets (defaults to the full cartesian product of all ranges).
`PACKET_COUNT:` in a program must be a positive integer; it cannot be combined
with `-c`. Duplicate variable names are rejected.

## Layout

- `src/` — lexer, parser, AST, registry, validators, checker, value/constructor
  types, serializer, generator, pcap writer, DPDK bindings + live runtime, CLI
- `csrc/` — C shim wrapping the DPDK macros / inline helpers the C3 side needs
- `test/` — unit tests
- `examples/` — sample packet programs (copied from packet_editor)

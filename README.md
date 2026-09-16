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
  `GeneratedPacket.payload_for_flow()` / `apply_flow()` then patch a
  specific flow index into a payload buffer (indexing each range
  modifier and re-running the fixup plan), so millions of flows expand
  without re-serializing.
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
  `PKG_CONFIG_PATH=/opt/dpdk/lib/x86_64-linux-gnu/pkgconfig`). The optional
  `ffg-dpdk` target in `project.json` wires the C shim (`c-sources`, `c-include-dirs`, `cflags` with
  `-include rte_config.h`), the DPDK shared libraries + TAP/vdev/mempool_ring
  drivers, and `-Wl,-rpath,/opt/dpdk/lib/x86_64-linux-gnu`.
- A unit test (`test/runtime_dpdk_test.c3`) links DPDK and checks
  `apply_dpdk_offload` mbuf metadata (mirrors
  `RuntimeTest.AppliesDpdkOffloadRequestToMbufMetadata`).
- **e2e transmit/capture needs root and TAP access** (`CAP_NET_ADMIN`,
  `/dev/net/tun`); the check path and the offload test run without privileges.

## Build

Requires [c3c](https://github.com/c3lang/c3c) 0.8.4. The default target builds
on macOS and Linux without any DPDK headers or libraries.

```bash
c3c build
c3c test
c3c run -- --check examples/native_tap.packet
```

DPDK is opt-in: `c3c build ffg-dpdk` / `c3c test ffg-dpdk`. This target
retains the existing `/opt/dpdk` Linux x86-64 installation paths and produces
`build/ffg-dpdk`. `project.e2.json` remains the XSL-specific configuration.

### Backend configuration

Choose the backend in the packet file; there are no `--backend` or `--interface`
runtime CLI options. Hash comments allow switching configurations:

```text
BACKEND: "tap"
INTERFACE: "packet_tap0"
# BACKEND: "dpdk"
# DPDK_ARGS: "--no-huge --no-pci -l 0"
PACKET: Ether()/IP()/UDP()
```

Only parsed, uncommented variables select the backend. Duplicate active
variables are errors. Legacy files containing `DPDK_ARGS` without `BACKEND`
still select DPDK with a migration warning. `--check` validates either backend
without opening devices or initializing EAL, including on macOS.

The native TAP backend uses Linux `/dev/net/tun` directly with software
checksums, independent TX/RX threads and multiqueue file descriptors. It supports
`PMD_THREADS`, `RX_THREADS`, `TX_BATCH_SIZE`, clone/split, continuous TX, once,
capture and interval statistics. Worker counts are limited to 128 combined;
PCAP capture uses one RX worker. A TAP packet must begin with `Ether()`.
`--dump-mempool-seed` is DPDK-only. TAP is a functional test backend, not a
DPDK throughput or offload substitute. With `--once` and RX enabled, TX finishes
one cycle and RX continues until SIGINT/SIGTERM, matching the DPDK runtime.

Creating/configuring TAP requires root or `CAP_NET_ADMIN`; the Python live
tests also use raw sockets. Temporary interfaces disappear when the final fd
closes (including after SIGKILL). Existing persistent interfaces remain and are
brought UP. Multiqueue runs require a multiqueue-capable persistent interface.

### Live mode (needs root)

```bash
# Validate a runtime program without touching the EAL:
./build/ffg --check examples/native_tap.packet

# Transmit one full pass over the flows on the TAP port:
sudo ./build/ffg examples/native_tap.packet --once

# Transmit continuously, cloning each flow 4x, with a live stats view:
sudo ./build/ffg examples/native_tap.packet --clone 4 --stats-interval 2

# Capture from the TAP port to a pcap (Ctrl-C to stop):
sudo ./build/ffg examples/native_tap.packet --capture out.pcap
```

Live flags: `--clone <n>`, `--split`, `--once`, `--stats-interval <sec>`,
`--capture [<out.pcap>]`. A program is treated as a live runtime program when it
declares `BACKEND` (or legacy `DPDK_ARGS`); `--check` forces validation instead.
For DPDK, use `build/ffg-dpdk` with `examples/tap_runtime.packet`.

### End-to-end TAP tests (needs root)

A `pytest`/`scapy` suite in `tests/e2e/` drives the built `ffg` over a native TAP
port and verifies the packets that reach the wire (normal L4, IP/TCP options,
VXLAN encapsulation, cartesian ranges, `--clone`/`--split` worker partitioning,
and `--capture`). It requires root, `/dev/net/tun`, `pytest`, and `scapy`.

```bash
pip install -r tests/requirements.txt
c3c build
sudo FFG_RUNTIME=$PWD/build/ffg python3 -m pytest tests/e2e/ -v
```

The **pytest** option `--backend tap|pcap|dpdk` selects the test transport;
it is not passed to the runtime. DPDK-only multiport/lcore tests are skipped
unless `--backend dpdk` is selected.

### macOS and local Lima tests

```bash
c3c build
c3c test
python3 -m pytest tests/cli tests/e2e --backend pcap --runtime "$PWD/build/ffg" -q
sh scripts/test-lima.sh
```

macOS runs unit tests and PCAP black-box tests without root. True Ethernet TAP
tests run inside the local Lima Linux VM; macOS `utun` is an IP interface, not
an Ethernet TAP replacement. Implementing an Apple Ethernet Network Extension
would require a separate signed app/extension and deployment setup, so it is
outside this CLI testing scope.

See [local testing](docs/local-testing.md) for Lima toolchain preparation,
isolated build paths, overrides and DPDK validation details.

## CLI

```bash
./build/ffg --check examples/native_tap.packet   # validate runtime program
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

### Range steps

Explicit integer, IPv4, and IPv6 ranges accept a decimal positive step:

```text
TCP(sport="1-100(step=2)")
IP(src="10.0.0.1-10.0.0.100(step=2)")
IPv6(src="2001:db8::1-2001:db8::ff(step=2)")
TCP(sport="[1-10(step=2), 20-30(step=3)]")
```

Each list entry may have its own step. The default is `step=1`. A step changes
the traversal order without reducing the range's flow space. Values advance by
the step and wrap inside the range; when the step and range length are not
coprime, traversal continues with the next congruence group. For example,
`1-10(step=4)` produces `1,5,9,3,7,2,6,10,4,8`, visiting every value once.
Steps are not supported on scalar values, CIDR ranges, descending ranges, or
with zero or negative values.

### Random ranges

Explicit integer, IPv4, and IPv6 ranges also accept `rand`:

```text
TCP(sport="1-100(rand)")
IP(src="10.0.0.1-10.0.0.100(rand)")
IPv6(src="2001:db8::1-2001:db8::ff(rand)")
TCP(sport="[1-10(rand), 20-30(rand)]")
```

The range still contributes its full size to the flow plan, but every
application selects a uniformly distributed value from the corresponding
range. `rand` takes no value and cannot be combined with `step`. DPDK builds
use the per-lcore `rte_rand()` generator; builds without the `DPDK` feature use
C3's thread-local runtime random generator.

## Layout

- `src/` — lexer, parser, AST, registry, validators, checker, value/constructor
  types, serializer, generator, pcap writer, DPDK bindings + live runtime, CLI
- `csrc/` — C shim wrapping the DPDK macros / inline helpers the C3 side needs
- `test/` — unit tests
- `examples/` — sample packet programs (copied from packet_editor)

### Multiple DPDK ports

The live runtime uses every available ethdev discovered after EAL initialization.
If EAL provides no ports, it creates the existing `packet_tap0` fallback.
`PMD_THREADS` and `RX_THREADS` are total worker counts: each enabled direction
must divide evenly across the ports. Worker IDs are global within TX/RX; queue
IDs restart at zero on each port. Omitted TX counts default to one worker per
port. RX is disabled by default during TX; capture-only defaults to one RX
worker per port. Provide enough EAL worker lcores for both totals.

For two TAP ports, this assigns two TX and two RX workers per port:

```text
DPDK_ARGS: "--no-huge --no-pci -m 256 -l 0-8 --vdev=net_tap0,iface=ffg0 --vdev=net_tap1,iface=ffg1"
PMD_THREADS: 4
RX_THREADS: 4
PACKET: Ether()/IP(src="[192.0.2.1-192.0.2.5]")/UDP()
```

`--split` distributes the complete flow set within each port's TX group; without
it, every TX worker sends the complete set. `PACKET_COUNT` applies to each port's
flow set. Live statistics and completion output group worker rows under each
port and retain overall totals. Device misses/errors are per-port counters;
RX bit rates use received bytes. `--capture <file.pcap>` remains single-port
only, while capture without a file supports all ports. Check-only results are
single-port estimates; actual worker defaults and totals resolve after EAL.

Driver constraints still apply: TAP requires equal configured TX/RX queue counts;
XSL requires a power-of-two RX queue count per port.

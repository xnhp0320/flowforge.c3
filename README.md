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
- The DPDK runtime is not implemented yet.

## Build

Requires [c3c](https://github.com/c3lang/c3c) 0.8+.

```bash
c3c build
c3c test
c3c run -- examples/tap_runtime.packet
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
# From a program file (uses its PACKET_COUNT: unless -c overrides it)
./build/ffg -w out.pcap examples/tap_runtime.packet

# From an inline expression, capping the range expansion at 12 flows
./build/ffg -w out.pcap -c 12 -e 'Ether()/IP(src="[10.0.0.1-10.0.0.4]")/TCP(sport="[10000-10002]",dport=443)'
```

`-w`/`--write <file>` selects file mode; `-c`/`--count <n>` caps the number
of generated packets (defaults to the full cartesian product of all ranges).

## Layout

- `src/` — lexer, parser, AST, registry, validators, checker, value/constructor
  types, serializer, generator, pcap writer, CLI
- `test/` — unit tests
- `examples/` — sample packet programs (copied from packet_editor)

Later phases: DPDK runtime.

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

## Phase 2 (in progress)

Adding the constructor stage, porting `PacketConstructorBuilder` from the C++
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
- The serializer, pcap writer, and DPDK runtime are not implemented yet.

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

## Layout

- `src/` — lexer, parser, AST, registry, validators, checker, value/constructor
  types, CLI
- `test/` — unit tests
- `examples/` — sample packet programs (copied from packet_editor)

Later phases: serializer, pcap writer, DPDK runtime.

# FlowForge (C3)

C3 port of [FlowForge](../packet_editor) — a Scapy-like packet DSL for DPDK traffic generation.

## Phase 1 (current)

DPDK-free pipeline using **C3 stdlib only** (no vendor bindings):

```
Lexer → Parser → Checker
```

- Parses `.packet` program files and inline packet expressions
- Validates headers and attributes against a built-in protocol registry
- Unit tests mirror the original C++ lexer/parser/checker tests

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

- `src/` — lexer, parser, AST, registry, validators, checker, CLI
- `test/` — unit tests
- `examples/` — sample packet programs (copied from packet_editor)

Later phases: constructor, serializer, pcap writer, DPDK runtime.

# C3 Idiom Review — flowforge.c3

Review date: 2026-10-06. Whole-project review (9,670 lines: src/ 19 files, test/ 12 files) for non-idiomatic C3, against c3-lang.org conventions.

## Status (branch `refactor/c3-faults`)

**Done — fault migration (front-end + value layer):**
- lexer/parser/ast converted to `T?` fault returns with `!` rethrow; parser detail via `last_error` side channel; `Parser.init` no longer drops priming errors
- cvalue range-list parsers deduped via `@parse_range_list` macro (kept `Result{T,String}` deliberately: checker tests pin detailed messages, faults carry no payload)
- validate collapsed from 11 public fns to `validate_scalar_type` (dead wrappers/aliases removed)
- checker `CheckResult.ok` flag → derived `ok()` method
- registry: double/triple map lookups fixed; `Registry.free` now frees inner allocations (was leaking per-spec arrays); `register_inference_rule` `bool?` → `void?`
- file_program: catch-and-bool optional handling → `try`/provably-valid pointer
- value: `hex_val` `-1` sentinel → `char?` fault

**Deliberately not converted to faults** (recorded rationale): cvalue/validate keep `Result{T,String}` — detailed diagnostics are their payload and checker tests assert message content; constructor/generator/serializer/runtime keep their aggregation structs (`BuildResult`, `SerializeResult`, `Result`) for the same reason; those structs' internal leaf fns are future work.

**Done — serializer/generator/CLI/runtime/pcap:**
- serializer: apply_fixup_plan pair unified (~260→1 body, 4→1 edit site for checksum fixes); plan_packet_fixups VXLAN/flat branches unified via PlanSlot helpers; range_at_index/total_*/make_* triplets via macros; named header-offset constants; write_bytes slice copy; dead faultdef removed; ipv6_range_count + add_ipv6_offset replaced with native uint128 arithmetic (~35 lines → ~10 lines)
- generator: apply_flow variants unified (validate/checksums_only knobs); dup_*_ranges via @dup_ranges macro; ULONG_MAX → ulong::max
- runtime/runtime_live: stop flag Atomic{bool} (was a cross-thread data race); split_dpdk_args → String[]? fault; std limits; magic 8191; double-init removed; defer teardown verified single-exit (finding was stale)
- CLI: parse_positive_arg helper (3 deduped option parsers); --capture ambiguity fixed (capture file only consumed after positional input; e2e order preserved); PACKET: prefix helper
- pcap: PcapWriteResult deleted, void? fault returns, dead `written < 0` check removed
- dpdk/stats: dead FF_OFFLOAD_L3_* removed, reset_offload single zeroing, math::abs

**Done — tests:**
- build_default/build_with/byte_at consolidated into testutil; checker_test 642→469 lines via check_default/check_with_header; runtime_test re-export deleted; if(catch)+assert(false) → `!!`; bytes_equal → slice `==`

**Still open (deliberately deferred, with rationale):**
- runtime_live helper layer `bool + List{String}*` → fault conversion: rc checks already centralized; DPDK paths only fully exercisable with a real EAL (unit tests cover the shim-backed subset). Same rationale for raw `rte_*` extern wrapping in dpdk.c3.
- Lexer-test `assert_token` macro / `@test` module-annotation consistency: cosmetic, no behavior.
- `header_file.c3` / `constructor.c3` internal bool+errors leaf fns: aggregation structs stay by design.

**Toolchain blocker resolved:** the `uint128` miscompilation reported on c3c 0.8.3 (swapped 64-bit limbs on 128-bit subtraction at `-O0`) no longer reproduces on c3c 0.8.5. The byte loops in `serializer.c3` were replaced with native `uint128` load/add/sub/store helpers; IPv6 range expansion and offset application verified by unit tests and wire-format audit.

## Executive summary

**Systemic issue (touches ~every file):** the project reinvents error handling instead of using C3 faults. Fallible functions return `std::collections::result::Result{T, String}` and every call site pays a 2-line rewrap tax (`if (!r.is_ok) return result::err(r.error)`). Faults (`fn T! f()`, `?`, `if (catch)`) are typed, matchable via `@catch`, and allocation-free; `string::tformat` errors allocate even when only tested ok/fail. Sub-patterns: `Result{bool, String}` with a phantom `true` payload (should be `void!`); `bool ok` flags duplicating `errors.len() == 0`; bool + `List{String}*` out-param error lists; sentinel returns (-1 / 0 / null meaning "error").

**Correctness bugs found:** non-atomic cross-thread stop flag (runtime_live.c3:50); `Registry.free` leaks per-spec arrays (registry.c3:455-461); `--capture` CLI arg ambiguity (main.c3:~477); dead `written < 0` check (pcap.c3:70).

**Highest-leverage changes:**
1. Migrate front-end pipeline (lexer→parser→validate→checker) to faults first (~120-150 lines removed in 6 files; cascades into constructor/registry/cvalue/main).
2. Extract duplicated fixup blocks in serializer.c3 (~300 lines, checksum fixes applied 2-4× today).
3. Consolidate the three range-list parsers in cvalue.c3 onto `String.tsplit(",")` (~100 lines).
4. Replace 16-byte borrow/carry loops with native `uint128` (serializer.c3:226-325).
5. runtime_live.c3: acquire-then-`defer` teardown + fault returns in the helper layer.

## Per-module reports (verbatim from reviewers)


---

# C3 Idiom Review: front-end (lexer/token/parser/ast/checker/validate)

## HIGH

### H1. Systemic: `Result{T, String}` + `is_ok` rewrapping instead of C3 faults (all files)
The whole front-end uses `std::collections::result::Result{T, String}` with `result::ok(...)`/`result::err(string::tformat(...))`, and every call site pays a 2-line tax:
- `src/parser.c3:20-21` — `Result{Token, String} next = self.lexer.next(); if (!next.is_ok) return result::err(next.error);` (repeated ~15× in parser.c3 alone: lines 20,104,111,122,129,155,168,180,189,194,...)
- `src/lexer.c3:37,45,64,96,113` — all lex fns return `Result{Token, String}`.
- `src/validate.c3:8-60,84-107` — every validator returns `Result{bool, String}`.
- `src/checker.c3:69-72` — `if (!valid.is_ok) { ...valid.error }`.

Idiomatic C3: `fn Token! Lexer.next(&self)` with `faultdef UNTERMINATED_STRING, UNEXPECTED_CHAR;` etc., callers write `Token t = self.lexer.next()?;` or `if (catch err)`. This deletes roughly a third of parser.c3/validate.c3 lines, keeps typed errors (matchable via `@catch`), and removes the stringly-typed error channel. `string::tformat` messages can still be produced at the top-level error printer via a `fault → message` mapper. This is the single highest-impact cleanup in the project.

### H2. `Result{bool, String}` where `ok` is always `true` — should be `void!`
- `src/validate.c3:8,14,21,28,34,42,48,56,84,102,109` — every validator returns `result::ok(true)` on success; the `bool` payload carries zero information.
- `src/parser.c3:18` `Parser.consume` — only ever returns `ok(true)`.
- `src/checker.c3:69` consumes `Result{bool,String}` and only reads `.error`.
Idiom: `fn void! validate_mac(String s)`; success is the absence of a fault. Even keeping Result, the payload should be a unit/void, not a phantom bool.

### H3. `CheckResult.ok` duplicates `errors.len > 0` (flag + collection pattern)
- `src/checker.c3:10-13,28` — `struct CheckResult { bool ok; List{String} warnings; List{String} errors; }`, with `result.ok = false` manually kept in sync at 4 sites (lines 38,53,68(?),73) and `result.ok = result.ok && nested.ok` at :52.
Idiom: drop the flag; `fn bool CheckResult.ok(&self) => self.errors.len() == 0;` (or `is_ok` method). Removes an invariant that can silently desync.

### H4. Faults flattened into strings, discarding typed error info
- `src/validate.c3:9-11` — `MacAddr? mac = value::mac_parse(s); if (catch mac) return result::err(string::tformat(...));` converts an already-typed fault into a string.
- `src/validate.c3:15-17,22-24` — same for `net::ipv4_from_str`/`ipv6_from_str`.
- `src/parser.c3:90-91` — `long? value = num.to_long(base); if (catch value) return result::err(...)` (this one at least adds context, acceptable, but with faults it'd be `return value?~INVALID_INT;` style or just propagate).
- `src/validate.c3:76-81` — `type_name[1..^8].to_ulong()` fault → `UNKNOWN_TYPE~` (this one does use a faultdef, good — but the surrounding API then re-strings it).
Idiom: propagate with `?`, or `?? `/`catch` mapping to a domain `faultdef INVALID_MAC;` etc., formatting to text only at the UI boundary (checker/main).

## MEDIUM

### M1. Copy-paste validator wrappers — macro or one-liner candidates
- `src/validate.c3:28-59` — six near-identical bodies: `Result{X,String} r = cvalue::parse_x(s); if (!r.is_ok) return result::err(r.error); return result::ok(true);`.
With faults each collapses to `fn void! validate_ipv4_range(String s) => cvalue::parse_ipv4_range(s)?;` — or a single `@macro`/`$foreach` over the parse fns. `validate_ipv4_range`/`validate_ipv6_range` (:40,:54) are pure aliases of `parse_ipv4_range`/`parse_ipv6_range` — dead indirection, pick one name.

### M2. Duplicated tagged unions `Expression` vs `ScalarValue`
- `src/ast.c3:16-28` vs `49-60` — identical shape (kind enum + union of String/long/Packet) with parallel enums `ExpressionKind`/`ScalarKind` and an `evaluate` (:64) that is a pure 1:1 copy constructor. `parser.c3:140-145 scalar_to_expression` converts right back.
Idiom: one `distinct`/shared struct or a single type used for both; at minimum share the payload union. The `default: return result::err("unsupported scalar value")` in scalar_to_expression is unreachable noise that an exhaustive enum switch (no default) would make a compile error instead.

### M3. Redundant `break` in `switch` cases
- `src/lexer.c3:101-108` — `case '=': type = ...; break;` ×6 plus `break;` at :59 inside the escape switch; also `src/parser.c3:45-50`.
C3 cases do not fall through (fallthrough requires `nextcase`); the `break`s are C-ism noise. Also, `lex_symbol`'s switch could return the token directly per case instead of assigning `type` then building after.

### M4. Non-exhaustive switch papered over with `default` err
- `src/parser.c3:140-146` — switch over `ScalarKind` (3 members) with `default: return result::err(...)`. With enum-exhaustive switches (and fault returns), delete the default so adding a 4th kind is a compile error.
- `src/token.c3:22-34` `token_type_name` is correctly exhaustive — but it must return on every path; if a member is added the missing-return is caught, fine. Note: could be a method `fn String TokenType.name(&self)` / or use the enum's `.name` reflection for the simple cases.

### M5. C-style indexed loop where iteration is only over a slice
- `src/parser.c3:38-72` — `for (usz i = 0; i < content.len; i++)` over `content` with manual `i += 3`/`i++` skipping. Index skipping makes `foreach` awkward, so a `while (i < content.len)` with explicit advance is the cleaner C3 form; at minimum use slice windows `content[i+1..i+3]` rather than repeated `content[i + 2]` indexing. LOW-MEDIUM payoff; the bug-prone part is the double increment (`i += 3` then `i++`).

### M6. Lexer negative-number handling mutates token after the fact
- `src/lexer.c3:123-131` — peeks `-`, advances, lexes number, then reaches back into `tok.value.lexeme`/`position` to patch. Cleaner: pass `start` into `lex_number` (or lex `-` as part of the number scan) so the token is built once. Also note `-` alone is then an "unexpected character" via lex_symbol — fine, but the special case belongs inside `lex_number`.

### M7. `validate_or_exit` should be `@noreturn`-aware / return exit code
- `src/checker.c3:86-96` — calls `os::exit(1)` mid-library. Not wrong for a CLI, but idiomatic layering returns a `bool`/fault and lets main call `os::exit`; if kept, the doc should note it may not return. LOW-MEDIUM.

## LOW

- **L1 `src/ast.c3:92`** — `faultdef NO_VALUE;` declared at the bottom of the file after its uses; C3 allows it, but convention puts faultdefs near the top with the types. Also `attr_scalar` wrapping `Maybe.get()`'s fault into a new fault loses the original — consider returning the Maybe's fault directly (`attr.value.get()?` then `return evaluate(expr)?;` — actually `evaluate` is itself `ScalarValue?` but can never fail; see L2).
- **L2 `src/ast.c3:64-74`** — `fn ScalarValue? evaluate(Expression expr)` never returns a fault (switch is exhaustive over 3 kinds). The `?` forces every caller (`parser.c3:245`, `checker.c3:47`, `constructor.c3:51`) to `if (catch)` an impossible error. Make it `fn ScalarValue evaluate(...)`.
- **L3 `src/lexer.c3:14-15`** — `init` builds an EOF token with `source[source.len..]` empty-lexeme trick; works, but a comment or a tiny `eof_token(source)` helper would document intent. Cosmetic.
- **L4 `src/parser.c3:34,72`** — `.copy(tmem)` after building in a temp DString is fine; but `out.str_view().copy(tmem)` copies temp→temp; `out.copy_str(tmem)`... actually DString already lives in tmem via `dstring::temp_with_capacity`, so `out.str_view()` is sufficient unless the DString is later mutated — the extra copy is likely redundant. Verify; potential wasted alloc.
- **L5 `src/validate.c3:67-81`** — `is_bit_ranges_type` magic `len > 8 && type_name[0] == 'b'` + `type_name[1..^8]` slicing: works, but a small doc-comment `<* *>` explaining the `bN` / `bN_ranges` grammar would help; the string-poking would be clearer via `type_name.starts_with("b") && type_name.ends_with("_ranges")`.
- **L6 `src/checker.c3:96,98`** — `checker_with_default` uses `mem::tnew` (temp allocator) for a Registry that outlives the temp scope if called outside `@pool()`; callers must be in a pool — worth a `<* @require ... *>` doc note. Not changed code-wise, just document.
- **L7 `src/parser.c3:167-176`** — `while (true) { ... if COMMA ... else break; }` is fine; idiomatic alternative `do { ... } while (peek == COMMA)` — taste, skip if preferred.

## Positive notes (already idiomatic)
- `checker.c3:18` uses a doc-comment contract `<* @param [&in] self ... *>` — good, extend this pattern to other public fns.
- `Maybe{Expression}` for optional attribute values (ast.c3:5-7) is the right std-lib optional; `if (catch expr) continue;` at checker.c3:46 is idiomatic.
- `List{T}` + `.tinit()`, `DString temp_with_capacity`, `string::tformat`, `std::net` parsing, exhaustive enum switches in token.c3, `alias Packet = List{Header}` — all good C3.
- `raw[^1]`, `raw[1..^2]`, `num[1..]` slice indexing used correctly throughout.

## Summary
- HIGH: 4 findings (H1 is systemic, touching ~60 call sites across all 6 files — adopting `fn T!` + `?` is the dominant cleanup)
- MEDIUM: 7 findings
- LOW: 7 findings
Total: ~18 findings. Estimated removable boilerplate if H1+H2 land: ~120–150 lines in these six files alone, plus ripple simplification in constructor.c3/registry.c3/cvalue.c3/main.c3 which consume the same Result API.
---

# C3 idiom review: constructor.c3, registry.c3, value.c3, cvalue.c3

Note: `Result{T, String}` / `Maybe{T}` here come from `std::collections::result` / `std::collections::maybe` and are used consistently project-wide, so they are "legal" — but they are the exact manual error-code/optional patterns C3 faults (`fn T!`, `?`) exist to replace. Findings on them are ranked accordingly (design-level, not per-call nitpicks).

## HIGH

1. **cvalue.c3:128-160, 205-237, 275-322 — three ~40-line copy-pasted range-list parsers.** `parse_uint_ranges` / `parse_ipv4_ranges` / `parse_ipv6_ranges` are byte-for-byte identical except element type and inner parse call, including the same hand-rolled comma scanner (`while (start <= content.len) { sz? comma = content.index_of_char_from(...) ... }`). Non-idiomatic duplication and reinvention of the stdlib: C3 strings have `String.split(allocator, ",")` / `tsplit`, so the body collapses to `foreach (i, part : s[1..^2].tsplit(",")) { String item = part.trim(); ... ranges.push(parse(item)?); }`, and the three functions collapse into one generic/macro (`macro parse_ranges($Type, raw, bit_width, $parse_fn)` or a `$generic` fn). Removes ~100 lines and one bug-surface.

2. **Pervasive `Result{bool, String}` with a useless `bool` payload** — cvalue.c3:61 `validate_bit_value`, registry.c3:242 `validate_constructor_value`, registry.c3:306 `integer_fits`, validate.c3 wrappers. Every success path is `return result::ok(true)` and callers only read `.error` / `.is_ok`. The C3 idiom is `fn void! validate_bit_value(...)` returning a fault, callers write `validate_bit_value(v, w) ?? ...` or `if (catch err)`. The `bool` payload is noise and every call site pays `if (!r.is_ok) return result::err(r.error);` boilerplate instead of `?` propagation. Same applies to `Result{Token,String}`-style helpers elsewhere, but these three are pure validation and gain the most.

3. **Error strings as the error channel.** cvalue.c3/constructor.c3 build every error with `string::tformat(...)` into `result::err(String)`. Faults are free, typed, and don't allocate; `string::tformat` allocates in the temp allocator even for errors that are then re-wrapped and re-formatted (e.g. constructor.c3:404 re-wraps `nerr` in another tformat). Idiom: `faultdef` per failure class (`faultdef INVALID_VALUE;` etc.) and format only at the user-facing boundary. With `String` payloads you also lose programmatic matching.

## MEDIUM

4. **value.c3:7-12 `hex_val` returns `-1` sentinel.** `fn int hex_val(char c)` → `-1` on invalid is a home-grown optional; idiom is `fn char? hex_val(char c)` returning a fault (`return INVALID_HEX~;`), callers `if (catch) return INVALID_MAC~;`. Callers at value.c3:25-27 then lose the awkward `int high/low; if (high < 0 ...)` checks.

5. **registry.c3:179 `register_inference_rule` returns `bool?` whose only success value is `true`.** `return true;` at the end, four `INFERENCE_ERR~` exits — should be `fn void! Registry.register_inference_rule(&self, ...)`. The `bool` is never meaningfully false.

6. **registry.c3 double/triple map lookups.** `Registry.has_attr` (registry.c3:430-434): `has_key` then `.get(protocol)!!` — two hash lookups; idiom: `StringSet? names = self.attr_names.get(protocol); if (catch names) return false; return names.contains(attr);`. `Registry.attr_type` (437-442) does *four* lookups (`has_key`+`get!!`, then `has_key`+`get`); rewrite as two `if (catch ...)` optional chains. `failing_type_message` (449-452) same pattern. Also registry.c3:210-217: `has_key` + create + `get_ref(key)!!` — could use `get_ref` once and create on catch.

7. **String-sniffing of type names duplicated in three places.** `type_name.len && type_name[0] == 'b'` appears in cvalue.c3:9/26, constructor.c3:86, registry.c3:265, each with its own re-parse of the width. Centralize as one `fn usz? cvalue::bit_field_width(String type_name)` and have callers use it — removes a class of drift bugs (cvalue.c3 already bounds `bN` to 1..64 in one place and relies on callers agreeing).

8. **constructor.c3 `header_option_bit_width` / `payload_bit_width` / `integer_option_value` mix faults and error lists with ambiguous 0-returns.** `header_option_bit_width` (constructor.c3:206) pushes to `errors` and `return 0;` — 0 means both "no options" and "error"; `integer_option_value` (constructor.c3:178) pushes a message *and* returns `BUILD_ERR~`, so callers must `if (catch) return 0` — the fault carries zero information. Idiom: return `usz?` and let the fault be the signal, keeping `errors` only for message text; or return a small struct `{ usz bits; bool had_error; }`. At minimum document the contract with `<* ... *>`.

9. **cvalue.c3:13 / constructor.c3:76 list-bracket detection is asymmetric and duplicated.** `if (!(s.len && s[0] == '[') && !s.ends_with("]"))` treats "starts with [ OR ends with ]" as list-ish (constructor.c3:76 has the same shape with `raw.contains("-")` added). `s.starts_with("[")` reads better than `s.len && s[0] == '['`, and the condition should be one helper (`fn bool looks_like_range_list(String s)`). Also constructor.c3:76 routes *any* string containing `-` to the range parser, relying on the range parser to reject plain ints — works but obscure.

10. **constructor.c3:429-447 unknown-attribute check: two break-flag loops per name.** `foreach (name : attrs.tkeys())` then linear scans of `header_spec.fields` and `.options` with `known_field/known_option` bools. The registry already maintains `StringSet` attr names — `if (!reg.has_attr(protocol, name))` (after fixing #6) or a helper `HeaderSpec.has_attr(String)` using `foreach` with early `return` would read better and be O(1).

11. **registry.c3 `Registry.free` leaks spec contents.** `register_header` allocates `field_list.to_array(self.allocator)` / `option_list.to_array(self.allocator)` and `inference_rules` `List`s with `self.allocator`, but `free` (registry.c3:455-461) frees only the maps. With a heap allocator the arrays/lists leak. Idiom: iterate `header_specs` / `inference_rules` and free the inner arrays (or document that Registry requires an arena/temp lifetime).

12. **apply_inference_rules C-style indexing with casts** (constructor.c3:298-305): `for (usz i = 0; i + 1 < n; i++) { constructor.get_ref((sz)i); constructor.get_ref((sz)(i + 1)); }`. `List.get_ref` takes `usz`, so the `(sz)` casts are noise; better: `HeaderConstructor[] headers = constructor.array_view();` then index `headers[i]`/`headers[i+1]`, or take the `List` by value. Same for `result.packet.get_ref((sz)result.packet.len() - 1)` at constructor.c3:471 — `result.packet.last()` doesn't exist but a slice view avoids the cast.

13. **value.c3 `cv_equals` indexed loops** (value.c3:190-212): `for (usz i = 0; i < a.ipv4_ranges_val.len; i++)` — idiom: `foreach (i, r : a.ipv4_ranges_val) { if (!ipv4_range_equals(r, b.ipv4_ranges_val[i])) return false; }`. Also the whole switch could delegate byte-array compares to a small `fn bool IPv4Range.op_eq?`/equals method; as-is it's fine but the UINT_RANGES case hand-compares `.first`/`.last` where `a.uint_ranges_val[i] == b...` (struct `==`) would work.

## LOW

14. **constructor.c3 BuildResult.ok is derived state** (constructor.c3:36): `ok` is set true only when `errors.len == 0` and callers elsewhere (main.c3, runtime) could check `errors.len == 0`; keeping both risks skew (there is a window where errors is empty but ok is false until line 480). Either drop `ok` or compute via a method `fn bool BuildResult.ok(&self) => self.errors.len == 0;`.

15. **value.c3:60-75 `IPv6.to_string` — 8 copy-pasted `(self.bytes[2i] << 8) | self.bytes[2i+1]` arguments.** A loop over a DString or a helper `fn ushort group(char[16] b, usz i) => ...` with a `string::tformat` per group would be shorter; `%04x` formatting per group also loses canonical `::` compression, but that may be intended.

16. **value.c3:137-175 nine `cv_*` constructor functions** differing only in enum tag and union field — a `@macro` would kill the repetition: `macro ConstructorValue @make($kind, #field, v) => { .kind = $kind, .$field = v };`. Payoff is modest; flag only because it's exactly the repetition macros exist for.

17. **registry.c3:222 `inference_key` uses `\x1f` separator + a `tformat` allocation per lookup.** `string::tformat("%s\x1f%s", ...)` in `find_inference_rules` (a read path) allocates in tmem every call. Nested map `HashMap{String, HashMap{String, List}}` or a struct key with custom hash avoids both the allocation and the (theoretical) collision if a header name ever contained `\x1f`.

18. **faultdef placement**: `faultdef BUILD_ERR` (constructor.c3:9), `faultdef INFERENCE_ERR` (registry.c3:178), `faultdef NO_ATTR` (registry.c3:444) scattered mid-file; C3 convention is faultdefs near the top with the other declarations.

19. **constructor.c3:50-62 `scalar_attribute_value` / `packet_attribute_value`** re-implement fault→String translation per call site; with faults (#3) these become two-line wrappers using `?`.

## Summary
HIGH: 3 (parser triplication/manual split, bool-payload Results, String-error channel). MEDIUM: 10 (sentinel -1, bool? rules, double map lookups, type-name sniffing x3, ambiguous 0-returns, registry leaks, indexing casts, break-flag loops, cv_equals loops). LOW: 7 (derived ok flag, to_string boilerplate, cv_* macro-able, inference_key alloc, faultdef placement, wrapper noise). The single highest-value change is consolidating the three range-list parsers in cvalue.c3 onto `String.split` + one generic body; the broadest is migrating validation-style functions from `Result{bool,String}` to `void!` faults.
---

## HIGH

1. **src/serializer.c3:53-58, 124-127, 129-133** — `struct SerializeResult { bool ok; String[] errors; ... }` (also FixupPlanResult, FixupResult). Home-grown bool+errors result pattern. The file already imports `std::collections::result` and uses faults elsewhere (`HeaderRef? find_header_ref`). Idiom: return faults — e.g. `fn char[]! serialize_packet(...)` (or `PacketFixupPlan!`) with `if (catch err)` / `?` at call sites; multi-error collection can stay a `List{String}` parameter, but `ok` should not be a separately-checked flag parallel to `errors.len == 0` (which is already the truth source, see :675-676).

2. **src/serializer.c3:226-259 `ipv6_range_count`, :316-325 `add_ipv6_offset`** — manual 16-byte borrow/carry loops over `char[16]`. C3 has native `uint128`; the whole subtraction + 'fits in u64' check becomes `uint128 diff = last.as_u128 - first.as_u128; return diff >= ulong::max ? ulong::max : (ulong)diff + 1;`. Fewer casts, no byte-loop bugs, much clearer.

3. **src/serializer.c3:1138-1293 vs :1046-1135** — `apply_checksum_fixup_plan` duplicates ~90% of `apply_fixup_plan` verbatim (outer_ipv4, ipv4, udp, tcp, icmp blocks) differing only in skipping length-field writes and using `l4_pseudo_sum_with_delta`. Also inside each function the UDP and TCP checksum blocks are near-identical, and `plan_packet_fixups` (:823+) repeats the same IPv4/IPv6/UDP/TCP/ICMP planning blocks twice (VXLAN branch :830-980 vs flat branch :982-1130). Idiom: extract small fns (`apply_ipv4_fixup(payload, fixup, write_lengths)`, `plan_ipv4(...)`, or `@macro`/`$foreach` over the fixup union). This is the biggest maintainability liability in the file — any checksum fix must be applied 2–4 times.

4. **src/serializer.c3:291-297, 301-307, 309-314 (`*_range_at_index`), :264-279 (`total_*_value_count`), :429-451 (`make_*_patch_ranges`)** — three copy-pasted triplets differing only in element type and count function. Idiom: a single `@macro range_at_index(#ranges, #value_index)` / generic-style extraction, or unify the three `*PatchRange` structs into one `PatchRange{T}`-shaped design so one fn serves all three.

5. **src/serializer.c3:1052-1135 and throughout fixup code** — magic header offsets/lengths: `+2` (total length), `+10` (IPv4 csum), `+4`/`+6` (UDP len/csum), `+16` (TCP csum), `+12` (IPv4 src), `+12 >>4` (TCP data offset), `20`, `40`, `8`. Idiom: named `const usz IPV4_HDR_LEN = 20;` / `IPV4_CSUM_OFF = 10;` etc. (the file already does this well with `TCP_PROTOCOL`/`UDP_PROTOCOL` at :11-12 — extend the convention).

## MEDIUM

6. **src/serializer.c3:561 `fn bool serialize_field(..., List{String}* errors)`** — bool-return + out-param error list. Idiom: `fn void! serialize_field(...)` returning a fault; the caller pushes context, or errors stay the single channel via a collected list but then return nothing. Mixed bool+list is the C-style pattern the checklist flags.

7. **src/serializer.c3:582-647 `make_modifier`** — returns `PayloadFieldModifier?` with `NO_MODIFIER~` meaning three different things: legitimate 'single value, no modifier needed', and *validation errors* (empty range lists) that are separately pushed into `errors`. Callers (`:677 if (try modifier)`) silently discard the distinction. Idiom: separate the 'no modifier' case (return the fault only for that) from validation failures, or return `Maybe{PayloadFieldModifier}` and let failures be real faults.

8. **src/serializer.c3:363 `fn Result{bool, String} PayloadFieldModifier.apply(...)`** — the ok payload is always literally `result::ok(true)`; a boolean that carries no information. Idiom: fault-based `fn void! apply(...)` or `Result{void, String}`; and per the checklist, prefer faults over `Result{T, String}` with `string::tformat` messages as the error type generally (same for `first_integer_value`/`first_ipv4_value`/`first_ipv6_value` :503-541 — these could return a single faultdef `BAD_FIELD_VALUE~` and push formatted context at the collection site).

9. **src/serializer.c3:416-426 `ipv4_pseudo_delta`** — returns `uint?` but uses plain `return 0;` for three different 'not applicable' conditions, so 0 means both 'no delta' and 'delta is zero'. Also `plan.ipv4.value.offset` etc. rely on `.has_value` checks — fine with Maybe, but the 0-sentinel is the home-grown-optional smell the checklist flags. Idiom: return a fault `NOT_APPLICABLE~` (or `Maybe{uint}`).

10. **src/serializer.c3:184-191 `write_bytes`** — C-style indexed copies `for (usz i = 0; i < bytes.len; i++) payload[byte_offset + i] = bytes[i];`. Idiom: slice copy `payload[byte_offset..byte_offset + bytes.len - 1] = bytes;` in the aligned branch, and `foreach (i, b : bytes) write_bits(...)` in the misaligned one.

11. **src/serializer.c3:681-693 `checksum_sum`** — manual `while (offset + 1 < len)` walking. Clearer with slice chunking or at least `for (; offset + 1 < bytes.len; offset += 2)`. LOW-MEDIUM clarity.

12. **src/serializer.c3:773-820** — `find_header_ref` / `find_header_ref_before` / `find_header_ref_after`: three near-identical search fns differing only in the offset predicate. Idiom: one fn taking a predicate lambda, or the `_before` variant implemented via the shared loop body. Also `find_header_ref_before` uses `bool has_found` + sentinel struct where `HeaderRef? found = HEADER_NOT_FOUND~;` inside would be awkward — acceptable, but extraction of the common match logic is worthwhile.

13. **src/serializer.c3:476-501 `find_field_spec`** — returns `FieldSpec*` with `null` on miss while every sibling lookup in the file (`find_header`, `find_header_ref`, `*_range_at_index`) uses faults. Idiom: `fn FieldSpec*? find_field_spec(...)` returning `NOT_FOUND~` (or `SEARCH_FAILED~`); callers currently do `if (!spec)` — inconsistent with the file's own convention.

14. **src/serializer.c3:1097-1105 (`push_fixup_error` + `bool has_errors` + lazy `errors.init(tmem, 1)`)** — hand-rolled lazy-list-init ceremony to avoid allocating an empty list. Idiom: just `List{String} errors; errors.tinit();` like `serialize_packet` (:653) and `plan_packet_fixups` (:825) already do, and check `errors.len() == 0` at the end. Deletes the helper and the parallel bool entirely; `tinit()` on an unused list costs nothing meaningful.

15. **src/serializer.c3:455-469 `payload_bit_width` / :543-560 `serialize_field`** — protocol and type dispatch on raw string compares (`"Payload"`, `"IP"`, `"TCP"`, `"mac"`, `"ipv4"`...). Idiom: `distinct` type-name or an enum on HeaderSpec/FieldSpec for well-known protocols, with switch instead of string-compare chains (also enables exhaustive-case checking).

16. **src/serializer.c3:11, 17-20** — `faultdef SERIALIZE_ERR, NO_MODIFIER, OUT_OF_RANGE, HEADER_NOT_FOUND;` and `faultdef PSEUDO_HEADER_MISSING;` (:1098) split across the file; `SERIALIZE_ERR` appears unused (grep shows no use site in the reviewed regions). Idiom: consolidate faultdefs; delete dead ones.

17. **src/serializer.c3:367, 658, 828, 834...** — error strings built with `string::tformat` are fine (tmem), but every failure allocates a formatted string even when the caller will only test ok/catch. With fault returns (finding 1/6/8) this cost moves to the error-collection site only. MEDIUM, folded into the error-handling rework.

## LOW

18. **src/serializer.c3:158-170 `write_bits`** — per-bit function call loop; fine for clarity, but the `((value >> shift) & 1) != 0` cast dance could be `(bool)(value >> shift & 1)`. LOW.

19. **src/serializer.c3:193-208 `read_u16`/`write_u16`/`write_u32`** — hand-rolled BE accessors with `(char)(value >> 8)` casts; consider `ushort.from_be`/`htons`-style helpers or a small `@macro` for the shift-cast pattern; at minimum consistent with std::bit ops if the rest of the codebase uses them. LOW.

20. **src/serializer.c3:348-361 `write_modifier_value`** — every `case` ends with bare `return;` and `case U32_BE: case IPV4:` stacked; works, but C3 idiom is case-block bodies (`case U8: payload[...] = (char)value;`) without trailing returns. Cosmetic.

21. **src/serializer.c3:222-224 `add_u16`** — one-line wrapper `sum + value` used 4 times in pseudo-sum builders; adds a name but no abstraction. Inline it. LOW.

22. **src/serializer.c3:211-220 `uint_range_count`/`saturated_add_count`** — saturation logic duplicated subtly with `ipv6_range_count`'s clamp; consider one `saturating_count(first, last)` helper. LOW.

23. **src/serializer.c3:824+ `plan_packet_fixups`** — 300-line function with two near-mirror branches; beyond the HIGH duplication item, idiom-wise this should be decomposed per protocol (`plan_ipv4_fixup(...)`, `plan_udp_fixup(...)`) which also shrinks the deep `if (try x) { if (...) { else { ... } } }` nesting (5 levels in places). LOW-MEDIUM.

24. **Result structs initialized via `FixupPlanResult result;` then fields set one by one at multiple return points (:672-679, :972-980)** — fine, but with faults (finding 1) these collapse to `return plan` / `return err~`. LOW.

25. **Missing `@nodiscard`** on `serialize_packet`, `plan_packet_fixups`, `apply_fixup_plan`, `apply_checksum_fixup_plan`, `PayloadFieldModifier.apply` — callers ignoring the result/errors would silently drop serialization failures. C3 supports the attribute; cheap safety. LOW-MEDIUM.

## Count summary
HIGH: 5 (error-model structs, uint128, fixup/plan duplication, range-fn triplets, magic offsets)
MEDIUM: 12 (bool+out-param serialize_field, NO_MODIFIER conflation, Result{bool,String} no-op payload, 0-sentinel pseudo_delta, slice-copy loops, checksum_sum loop, find_* triplication, null-vs-fault inconsistency, lazy-list ceremony, string-dispatch types, split/dead faultdefs, eager error formatting)
LOW: 8 (misc casts/loops, switch returns, add_u16 wrapper, saturation dedup, function size, @nodiscard, BE accessor helpers)
Total ≈ 25. Top payoffs: adopt native uint128 (#2), extract shared fixup blocks (#3), and replace the ok/errors structs with faults (#1).

---

## Findings (ranked)

### HIGH

**H1. Sentinel-return error pattern in checked_* helpers — runtime.c3:248-274**
```c3
fn ulong checked_transmission_count(...) { if (clone_count == 0) { ... return 0; } ... }
```
Returns `0` as an error sentinel (0 is also a legitimate-looking value; correctness relies on callers re-checking `result.errors.len()`). C3 idiom: return a fault, `fn ulong? checked_transmission_count(...)`, callers use `ulong n = checked_transmission_count(...)?;` or `if (catch n)`. Same for `checked_total_transmission_count`.

**H2. bool + `List{String}* errors` out-param pattern everywhere — runtime_live.c3 (~235 `check_tap_permission`, 243 `probe_tap_port`, 301 `configure_and_start_port`, 360 `transmit_batch`, 469 `run_traffic`, 520 `wait_for_all`...)**
```c3
fn bool check_tap_permission(List{String}* errors) @private { ... errors.push(...); return false; }
```
This is exactly the bool+out-param pattern C3 faults replace. Idiom: `fn void! check_tap_permission()`, push messages via `return TAP_ERR~` (or keep a `faultdef` per failure class), callers `try`/catch and translate to the warnings/errors list at the single boundary that builds `Result`. Would collapse the deep `if (!a) { ok=false; return; }` ladders in `Runtime.run`/`run_capture` into `?` chains.

**H3. Cross-thread stop flag is a plain `bool` — runtime_live.c3:50**
```c3
bool runtime_stop_requested @private = false;
```
Written by the signal handler / main thread, polled by DPDK worker threads with no synchronization. The file already uses `Atomic{ulong}` for published stats; this should be `Atomic{bool}` (`.store(true)` / `.load()`), or at minimum the flag should justify non-atomicity in the comment. Also drop the `= false` (C3 zero-initializes).

**H4. Manual cleanup ordering / duplicated teardown instead of `defer` — runtime_live.c3 run_capture (~1080-1165) and Runtime.run (~1020-1045)**
```c3
dpdk::rte_mempool_free(pool);
cleanup_eal(&result.warnings);
result.ok = false;
return;
```
This block (and `file close` variants) is copy-pasted three times in `run_capture` on early-error exits, then again at the tail — classic leak-on-new-early-return hazard. Idiom: acquire-then-`defer` — `defer dpdk::rte_mempool_free(pool);`, `defer cleanup_eal(&result.warnings);`, `defer if (port_started) stop_and_close_port(...);`, `defer if (have_file) (void)out.close();` immediately after each successful acquisition. Same in `Runtime.run` for pool/cleanup_eal/stop_and_close_port.

**H5. Home-grown optional `Maybe{ulong}`/`Maybe{String}` — runtime.c3:12, 33-34, 71-73 and 6+ uses**
```c3
result.pmd_threads = config.pmd_threads.has_value ? config.pmd_threads.value : 1;
```
`std::collections::maybe` is a home-grown optional in a language whose idiom is faults; worse, the `has_value ? .value : default` ternary is copy-pasted verbatim at runtime.c3:312-313, 328-329 and runtime_live.c3:984-985, 1056-1057. If `Maybe` must stay (external API), at least add/use a `Maybe.or(default)` helper; prefer redesigning `RunOptions`/`Config` to plain fields with explicit defaults resolved in one place (e.g. a `resolve_defaults()` returning a fully-populated struct).

### MEDIUM

**M1. `ULONG_MAX`/`USHORT_MAX` redefine std limits — runtime.c3:17-18**
```c3
const ulong ULONG_MAX = 0xFFFFFFFFFFFFFFFF;
```
Use `ulong::max` / `ushort::max` (the file itself already uses `ushort::max` at runtime_live.c3:141). The error strings at runtime.c3:257, 269 also hardcode the magic `18446744073709551615`.

**M2. `result::Result{String[], String}` instead of a fault — runtime.c3:96-135 `split_dpdk_args`**
```c3
return result::err("DPDK_ARGS ends with an unfinished escape");
```
Wrapping std's Result type to emulate `Either` is the pre-fault idiom. `fn String[]? split_dpdk_args(String args)` with `return SPLIT_ERR~` and callers `String[] parts = split_dpdk_args(x) ?? ...` is the C3 way; then `args.is_ok`/`args.error` juggling at runtime.c3:186 disappears.

**M3. Double error-channel in `positive_integer_var` — runtime.c3:138-153**
Returns `ulong?` (fault) *and* pushes a formatted message into `List{String}* errors`. Pick one: since callers only branch on failure, return the fault and let the single caller site push/format the message, or return `String?` message. Current shape makes every call site a two-line `if (try x) config...` dance (runtime.c3:204-243).

**M4. `Result.ok` bool kept in sync manually — runtime.c3:39 and runtime_live.c3 (~5 sites of `result.ok = result.errors.len() == 0`)**
Home-grown validity flag that can drift from `errors.len()`. Idiom: compute at read time (`fn bool Result.is_ok(&self) => self.errors.len() == 0;`) or construct the final Result once. Repeated `result.ok = false; return;` blocks in run_capture are fallout of H2/H4.

**M5. Raw libc externs scattered — runtime_live.c3:43-48**
```c3
extern fn void* signal(int signum, SignalHandler handler) @private;
extern fn int usleep(uint usec) @private;
const int SIGINT = 2;
```
Hand-declared `signal`/`usleep`/`time` plus magic `SIGINT=2`/`SIGTERM=15`. Stdlib ships `libc` (`import libc;`) with `libc::signal`, `libc::SIGINT`, etc.; wrapping these behind one `@private` `install_signal_handlers()` is good, but the declarations themselves should come from `libc` to avoid diverging constants. The checklist's "extern fns wrapped in safe APIs" is half-done here.

**M6. NUL-char as quote sentinel — runtime.c3:101-133 `split_dpdk_args`**
```c3
char quote = 0; ... if (quote != 0) { ... }
```
`0` doubles as "not in quote" — a magic-int sentinel. Idiom: `enum QuoteMode : char { NONE, SINGLE, DOUBLE }` or a `char?`-style bool+char pair; a bitstruct is overkill but a two-state enum reads cleanly in the `switch` this function wants to be.

**M7. `Config? config_opt = build_config(...); if (catch config_opt) return result; Config config = config_opt;` — runtime_live.c3:937-939, 958-960**
Redundant unwrap dance: after `if (catch config)` the optional is known-good, so `Config? config = build_config(...); if (catch config) return result;` lets `config` be used directly (implicit unwrap) — runtime.c3:309 already does it this way; make the two live entry points match.

**M8. `EthStats stats; stats = {};` — runtime_live.c3:590-591, 1142-1143**
Double initialization; C3 zero-initializes `EthStats stats;` already. Delete the `stats = {};` lines (same for `LiveStatsState state; state = {};` at 615-616).

### LOW

**L1. C-style indexed loops over slices — runtime_live.c3:309-321 (queue setup), 535-556, 705-715 (result aggregation), 556-566**
```c3
for (usz i = 0; i < tx_ctxs.len; i++) { ... tx_ctxs[i] ... }
```
Use `foreach (i, &ctx : tx_ctxs)` where the index is needed, plain `foreach (&ctx : tx_ctxs)` otherwise. Similarly `for (ushort i = 0; i < nb_rx; i++)` over mbuf arrays could iterate `mbufs[:nb_rx]`. Queue-setup loops (`queue_id++`) are fine as-is since only the index matters.

**L2. `free_unsent(Mbuf** packets, ushort begin, ushort end)` — runtime_live.c3:352-356**
Pointer + index range is C-style; take a slice `Mbuf*[] packets` and iterate `foreach (p : packets) dpdk::ff_pktmbuf_free(p);` — call sites become `free_unsent(packets[prepared..count-1])` or just `packets[prepared..]`, removing begin/end arithmetic bugs by construction.

**L3. Repeated `result.tinit(); result.clone_count = 1;` Result construction — runtime.c3:305-307, runtime_live.c3:932-934, 953-955**
Three identical open-coded constructors. Add `fn Result new_result() => { .clone_count = 1, ... }` (with lists tinit'd) or a `Result.init()` method that also sets the default — one place to change when fields are added.

**L4. Magic `8191` duplicated — runtime_live.c3:218 vs const RUNTIME_CAPTURE_MBUF_COUNT (line 31)**
`mbuf_count_for` clamps with literal `if (total < 8191) total = 8191;` while the same value exists as `RUNTIME_CAPTURE_MBUF_COUNT`. Reuse the const or name a `RUNTIME_MIN_MBUF_COUNT`.

**L5. `(short)i < (short)count - 1` — runtime_live.c3:441**
Cast-to-signed comparison for "not the last element"; `i + 1 < count` (both ushort) expresses it without casts. Same loop could hoist the prefetch via slice peeking.

**L6. `zstr()` helper partially applied — runtime_live.c3:63**
Fine helper, but `init_eal` and `check_tap_permission` still call `.zstr_tcopy()` directly (lines 190-193, 238). Use `zstr(...)` consistently or drop the alias — two conventions for the same operation in one file.

## Count summary
- HIGH: 5 (fault-less error plumbing ×2 patterns, non-atomic stop flag, missing defer teardown, Maybe-optional abuse)
- MEDIUM: 8
- LOW: 6
- Total ≈ 19 findings. Highest-leverage fix: convert the `@private` helper layer in runtime_live.c3 to fault returns + `defer` teardown (H2+H4) — it removes the most copy-pasted code and the leak hazard; H3 is a one-line correctness fix.
---

# C3 idiom review — ranked findings

## HIGH

**H1. pcap.c3:13-17,36-42,51-66 — home-grown result struct instead of faults.**
`struct PcapWriteResult { bool ok; String[] errors; }` plus a `single_error()` helper and `if (catch ...) { return single_error(...) }` wrappers. C3 already has fault returns: `OutStream.write_byte` returns `void!` and the module even declares `faultdef WRITE_FAILED` (used only once). Worse, the catch discards the real IO error and substitutes a generic "failed to write pcap output" string allocated into a temp List — pure boilerplate. Idiom: make `write_header`/`write_packet` return `void!` and let the original fault propagate (`self.write_header_bytes()!`); callers use `if (catch err)` / `?`. Deletes `PcapWriteResult`, `single_error`, and ~half the module.

**H2. pcap.c3:70 — dead check on a fault-returning call.**
`sz written = self.output.write(payload)!; if (written < 0 || (usz)written != payload.len) return WRITE_FAILED~;`
`OutStream.write` faults on failure, so after `!` a negative `written` is unreachable; the `< 0` half is dead C-thinking. Keep only the short-write comparison (or use `write_all`-style helpers if available).

**H3. main.c3:~477-483 — `--capture` swallows the program path.**
`else if (args[i] == "--capture") { ... if (i + 1 < args.len && !args[i + 1].starts_with("-")) { live_options.capture_file.set(args[++i]); } }`
An optional positional argument parsed by "next token doesn't start with '-'" is ambiguous: `flowforge --capture prog.packet` silently treats `prog.packet` as the capture file, leaving `input_path` empty → later `usage()` error with no hint. The usage line `[--capture [<out.pcap>]]` itself documents the ambiguity. Idiom: require an explicit value (`--capture <file>`), or use a distinct flag for the file (`--capture-file`), or only treat the next token as the file when a positional input was already seen.

**H4. file_program.c3:39-45,52 — optional handling via catch-and-bool instead of `try`.**
`Variable*? packet_var = variables.get("PACKET"); if (catch packet_var) {...}` then later dereferencing `packet_var` guarded only by a distant `if (result.errors.len()) return result;`; and `bool has_count_var = true; if (catch count_var) has_count_var = false;`. Idiomatic C3: `if (try packet_var = variables.get("PACKET")) { ... } else { error; return; }` — keeps the pointer provably valid in the success branch and deletes the boolean crutch.

## MEDIUM

**M1. main.c3:464-518 — triplicated positive-integer option parsing.**
`-c`, `--clone`, `--stats-interval` each repeat `if (i + 1 >= args.len) return usage(...); long? value = args[++i].to_long(); if (catch value) {...} if (value <= 0) {...}`. One helper (`fn ulong? parse_positive_arg(String s)` or a small `@macro`) collapses three copies and unifies the (currently divergent) error messages.

**M2. generator.c3:197-217 — three identical `dup_*_ranges` functions.**
`dup_uint_ranges` / `dup_ipv4_ranges` / `dup_ipv6_ranges` differ only in element type. Idiomatic C3: one generic via macro (`@macro dup_ranges($Type, src, alloc)`) or a single body over `void[]`+element size; better, check `slice.copy(alloc)`/std helpers first. Same copy-paste smell in the two `switch (m.values_kind)` blocks in `copy_modifiers` vs `GeneratedPacket.free` (lines ~180, ~230).

**M3. generator.c3:113-154 — three near-identical `apply_flow*` variants.**
`apply_flow`, `apply_flow_checksums_only`, `apply_flow_checksums_only_unchecked` share the modifier loop + fixup tail; the checked/unchecked split duplicates bounds checks. Factor the shared core into one private `fn bool apply_common(..., bool checked, bool lengths_too)`; keeps the hot-path variant without 3× maintenance.

**M4. generator.c3:258 / plan_flow_indexes — local `ULONG_MAX` constant.**
`const ulong ULONG_MAX = 0xFFFFFFFFFFFFFFFF;` plus a hard-coded decimal "18446744073709551615" in the error string. Use `ulong.max` (built-in) and format the bound via `%d` or just say "exceeds ulong range".

**M5. dpdk.c3:118-151 — extern C APIs exposed raw; only `strerror` is wrapped.**
Per the project's own doc-comment ("everything ... is reached through the C shim"), all `rte_*`/`ff_*` functions returning C error-code ints (`rte_eal_init`, `rte_eth_dev_start`, `ff_eth_dev_configure`, `ff_check_tap_permission`, ...) are bound naked. Callers elsewhere must do manual `< 0` checks — exactly the sentinel-error pattern C3 faults replace. Idiom: thin wrappers in this module, e.g. `fn void? eal_init(...) { if (rte_eal_init(...) < 0) return EAL_INIT_FAILED~; }`, so all consumers propagate with `?`. Also the `FF_OFFLOAD_L3_*` int constants (lines 72-75) mirror an enum — declare a real `enum OffloadLayer3 : (int)` to get exhaustiveness checking instead of magic ints.

**M6. main.c3:317 & 489 — duplicated `PACKET:` prefix stripping.**
`if (expr.starts_with("PACKET:")) expr = expr["PACKET:".len..].trim();` appears twice. Extract `fn String strip_packet_prefix(String s)`.

**M7. main.c3:331,353,538 — mode detection by substring sniffing.**
`content.contains("PACKET:")` / `content.contains("DPDK_ARGS:")` decides parse mode; a comment or string containing those bytes flips modes. Have the parser report the program kind instead (single source of truth), or anchor the check. Design smell rather than pure style, but the checklist's "boring design" applies.

**M8. header_file.c3 / generator.c3 / file_program.c3 — pervasive `bool ok` + `List{String} errors` instead of faults.**
Multi-diagnostic collection is a legitimate reason to keep lists (faults are single-error), so this is MEDIUM not HIGH — but several leaf functions don't need it: `Loader.parse_header` returns bool solely to mean "stop", `plan_flow_indexes`/`serialize_generated` push exactly one error then return false. Those could be `void!`/`T!` with a real fault (`faultdef PARSE_ERR`), leaving list-collection only at the top-level diagnostic aggregation.

**M9. header_file.c3:76,90 — tokenizer slice ranges.**
`content[i:1]` (fine C3 length-syntax) but `content[start:i - start]` mixes conventions; `content[start..i-1]` is the idiomatic range form and reads better.

## LOW

**L1. pcap.c3:22-34 — byte-at-a-time LE writes.** 2–4 virtual `write_byte` calls per field; build a `char[4]` and single `out.write(buf[..])!`, or use std endian write helpers if present. Clarity + minor perf.

**L2. stats_format.c3:12 — manual abs.** `double v = value; if (v < 0) v = -v;` → `math::abs(value)`.

**L3. main.c3:30-54 — enum→string switches.** Fine and exhaustive, but the module imports the enums; consider co-locating `fn String ModifierValueKind.name(&self)` methods on the enums in their defining modules so main.c3 (and any other printer) reuses them. Same for the `result.split ? "on" : "off"` inline at ~430 duplicating `bool_name`.

**L4. main.c3:56-63 — print_ipv4_ranges byte extraction.** Hand-built `char[4]` from shifts; a `value::ipv4_to_bytes(uint)` helper (or `bitstruct`) would document intent. Cosmetic.

**L5. main.c3:264,277 — `result::Result{...}` verbose paths.** `result::` prefix needed only because `Result` is otherwise unimported; `import std::collections::result;` is present, so `Result{Packet, String}` suffices (generator/file_program already use the short form). Consistency nit.

**L6. dpdk.c3:19-26 — bitstruct fields typed `ulong`.** Required by C3 (bitstruct field type must match base), so keep; but the five-field manual reset in `Mbuf.reset_offload` could be `self.tx_offload = {};` — one zeroing assignment instead of five stores.

## Count summary
HIGH: 4 (pcap result struct, dead `written<0`, `--capture` ambiguity, file_program optional handling)
MEDIUM: 9 (CLI parse triplication, dup_*_ranges, apply_flow* variants, ULONG_MAX, dpdk raw-extern wrapping + magic-int enum, PACKET: duplication, mode sniffing, bool+list overuse, slice-range style)
LOW: 6 (pcap byte writes, abs, enum name methods, ipv4 byte building, result:: prefix, tx_offload zeroing)
Total: 19 findings.
---

## Test-side C3 idiom review (test/*.c3)

### HIGH

**H1. `if (catch delta) assert(false)` instead of fault propagation — test/serializer_test.c3:357-358**
```c3
uint? delta = modifier.ipv4_pseudo_delta(plan.plan, 2);
if (catch delta) assert(false);
```
Non-idiomatic on two counts: (1) an optional captured with `if (catch)` and then *used after the block* relies on control flow that the compiler only narrowly accepts — the idiomatic form is `uint delta = modifier.ipv4_pseudo_delta(plan.plan, 2)!!;` (panic on fault, exactly what `assert(false)` does) or `try`; (2) `assert(false)` with no message is a worse `unreachable("expected pseudo delta")`. Suggested: `uint delta = modifier.ipv4_pseudo_delta(plan.plan, 2)!!;`

**H2. Duplicated test helpers across files — constructor_test.c3:8-26 vs serializer_test.c3:8-27, byte_at in serializer_test.c3:29 and file_mode_test.c3:9**
`build_default`, `build_with` are copy-pasted verbatim between constructor_test.c3 and serializer_test.c3; `byte_at` is copy-pasted between serializer_test.c3 and file_mode_test.c3. test/helpers.c3 (`flowforge::testutil`) already exists as the shared module — these belong there. Six-month maintainability: any signature change (e.g. build taking options) must currently be edited twice. Suggested: move all four into testutil and import.

**H3. Massive per-test boilerplate in checker_test.c3 — e.g. :24-30, repeated ~45 times**
```c3
Packet pkt = testutil::must_parse("...");
Checker checker = checker::checker_with_default();
CheckResult result = checker.check(pkt);
```
The same 3-line setup (and the 5-line `Registry reg = ...; reg.add_header(...); Checker checker = { .registry = &reg };` variant, repeated ~8 times e.g. :118-124, :386-392, :410-416) is exactly what `@macro`/helpers are for. Suggested:
```c3
fn CheckResult check_default(String input) { ... }
fn CheckResult check_with_header(String input, String name, String[] fields, String[] types) { ... }
```
or a `macro CheckResult @check(#input)` in testutil. Cuts ~200 lines and makes new tests one-liners.

### MEDIUM

**M1. Lexer tests: repeated `next().ok()!!; assert(type); assert(lexeme)` triple — test/lexer_test.c3, e.g. :10-13, :55-160**
~60 repetitions of the same triple; test_lexer_scapy_style alone is ~60 lines of it. Suggested macro in the file or testutil:
```c3
macro void @assert_token(Lexer* #l, TokenType #type, String #lexeme) {
	Token t = #l.next().ok()!!;
	assert(t.type == #type);
	assert(t.lexeme == #lexeme);
}
```
(Or, since the module is `@test`, a table-driven loop over `{type, lexeme}[]` with `foreach`.) Biggest readability win in the suite.

**M2. C-style indexed fill loop — test/serializer_test.c3:104**
```c3
for (usz i = 0; i < buf.len; i++) buf[i] = (char)0xff;
```
Idiomatic C3: `foreach (&b : buf[..]) *b = 0xff;` (or `mem::set(buf[..], 0xff)` if available for the target C3 version).

**M3. Hand-rolled `bytes_equal` with C-style loop — test/file_mode_test.c3:17-23**
```c3
for (usz i = 0; i < a.len; i++) { if (a[i] != b[i]) return false; }
```
Modern C3 supports slice equality directly (`a == b` compares contents); if pinned to an older compiler, at minimum use `foreach (i, x : a) if (x != b[i]) return false;`. Delete the helper if `==` suffices.

**M4. Inconsistent `@test` placement across modules**
lexer_test.c3:1, parser_test.c3:1, checker_test.c3:1, header_file_test.c3:1 use `module ... @test;` (which already marks every `fn void test_*` as a test) *and* still annotate each function with `@test` (redundant); the other 8 files annotate functions individually with a bare module. Pick one convention — module-level `@test` plus bare functions is the cleaner C3 idiom.

**M5. Field-by-field struct initialization instead of designated initializer — test/runtime_dpdk_test.c3:12-18, :34-40, :53-63, :82-86**
```c3
PacketOffloadRequest request;
request.layer3 = OffloadLayer3.IPV4;
request.ipv4_checksum = true;
...
```
C3 idiom: `PacketOffloadRequest request = { .layer3 = OffloadLayer3.IPV4, .ipv4_checksum = true, ... };` — one expression, no risk of a partially-initialized struct if fields are added later (designated init zeroes the rest deterministically at declaration).

**M6. Pointless re-export wrapper — test/runtime_test.c3:20**
```c3
fn Program must_parse_program(String input) => testutil::must_parse_program(input);
```
A function that only forwards to the helper it shadows by name; callers can just call `testutil::must_parse_program` as file_program_test.c3 does. Delete.

### LOW

**L1. Home-grown optional assertions in tests — file_program_test.c3:11-13, runtime_test.c3:172-174, file_mode_test.c3:30-31**
```c3
assert(result.packet_count.has_value);
assert(result.packet_count.value == 3);
```
Tests exercise `generator::MaybeCount` / `stats_interval_seconds` (has_value/value/set), a home-grown Option. Root cause is library-side (C3 has no Option type; a fault-returning accessor or `Type*`/null pattern would be more idiomatic), so fixing it is out of test scope, but the tests will all need touching when the library is cleaned up — flag for the library review.

**L2. Stale Rust-style doc reference — test/runtime_dpdk_test.c3:7**
`<* Mirrors RuntimeTest.AppliesDpdkOffloadRequestToMbufMetadata ... *>` references a Rust/C++ test naming scheme that doesn't exist in this repo; the comment on :116 ("mirrors C++ Runtime::init") is in src but same pattern. Either point at the real C3 counterpart or drop the cross-reference.

**L3. helpers.c3 functions have no `<* *>` doc comments — test/helpers.c3:5-13**
Minor: the shared helpers every test depends on lack the doc-comment convention used elsewhere in the project (e.g. runtime_dpdk_test.c3:7). One line each (`<* Parse a packet or abort the test *>`) would match house style.

### Verified non-issues (checked, not findings)
- No allocator leaks in tests: `Registry` creation is `tinit()`/tmem-backed (src/registry.c3:433-443), temp `List`s use `.tinit()` (parser_test.c3:252-263, file_mode_test.c3:46), and runtime_dpdk_test.c3 correctly uses `defer dpdk::ff_test_free_mbuf(mbuf)` after alloc. `buf[..]` slicing for checksum windows (serializer_test.c3) is idiomatic.
- `foreach (f : h.fields)` in get_field/get_option (constructor_test.c3:17-28) is already the idiomatic slice form.

### Count summary
HIGH 3, MEDIUM 6, LOW 3 — 12 findings total. The dominant theme: repetitive setup (H3, M1) and duplicated helpers (H2) account for roughly 400+ lines of removable boilerplate; only H1 touches fault-handling correctness/clarity.
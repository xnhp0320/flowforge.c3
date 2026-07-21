module flowforge;
import flowforge::ast;
import flowforge::parser;
import flowforge::checker;
import flowforge::file_program;
import flowforge::generator;
import flowforge::header_file;
import flowforge::pcap;
import flowforge::registry;
import flowforge::runtime;
import flowforge::serializer;
import flowforge::value;
import std::collections::list;
import std::io;
import std::io::file;

faultdef HEADER_LOAD_ERR;

fn int usage(String prog) {
	io::eprintfn("Usage: %s [--headers <file>] [--parse-only] <program.packet>", prog);
	io::eprintfn("       %s [--headers <file>] [--parse-only] -e '<packet expression>'", prog);
	io::eprintfn("       %s [--headers <file>] -w <out.pcap> [-c <count>] <program.packet>", prog);
	io::eprintfn("       %s [--headers <file>] -w <out.pcap> [-c <count>] -e '<packet expression>'", prog);
	io::eprintfn("       %s [--headers <file>] [-v|--verbose] [--clone <n>] [--split] [--once] [--stats-interval <sec>] <program.packet>", prog);
	io::eprintfn("       %s [--headers <file>] [-v|--verbose] --capture [<out.pcap>] <program.packet>", prog);
	return 1;
}

fn String bool_name(bool value) => value ? "on" : "off";

fn String modifier_kind_name(ModifierValueKind kind) {
	switch (kind) {
		case UINT_RANGES: return "uint_ranges";
		case IPV4_RANGES: return "ipv4_ranges";
		case IPV6_RANGES: return "ipv6_ranges";
	}
}

fn String fixup_mode_name(FixupMode mode) {
	switch (mode) {
		case SOFTWARE: return "software";
		case HARDWARE_OFFLOAD: return "hardware_offload";
		case DISABLED: return "disabled";
	}
}

fn String offload_layer3_name(OffloadLayer3 layer3) {
	switch (layer3) {
		case NONE: return "none";
		case IPV4: return "ipv4";
		case IPV6: return "ipv6";
	}
}

fn void print_uint_ranges(UIntRange[] ranges) {
	foreach (i, r : ranges) {
		io::printfn("      range[%d]: %d-%d", i, r.first, r.last);
	}
}

fn void print_ipv4_ranges(IPv4Range[] ranges) {
	foreach (i, r : ranges) {
		io::printfn("      range[%d]: %s-%s", i, r.first.to_string(), r.last.to_string());
	}
}

fn void print_ipv6_ranges(IPv6Range[] ranges) {
	foreach (i, r : ranges) {
		io::printfn("      range[%d]: %s-%s", i, r.first.to_string(), r.last.to_string());
	}
}

fn void print_modifiers(List{PayloadFieldModifier} modifiers) {
	io::printfn("modifiers: %d", modifiers.len());
	foreach (i, m : modifiers) {
		io::printfn("  modifier[%d]: %s.%s bit_offset=%d bit_width=%d value_count=%d kind=%s",
			i, m.protocol, m.field, m.bit_offset, m.bit_width, m.value_count, modifier_kind_name(m.values_kind));
		switch (m.values_kind) {
			case UINT_RANGES:
				print_uint_ranges(m.uint_ranges);
			case IPV4_RANGES:
				print_ipv4_ranges(m.ipv4_ranges);
			case IPV6_RANGES:
				print_ipv6_ranges(m.ipv6_ranges);
		}
	}
}

fn void print_fixup_plan(PacketFixupPlan plan) {
	io::printfn("fixup_plan: packet_len=%d vxlan_tunnel=%s", plan.packet_len, bool_name(plan.vxlan_tunnel));
	io::printfn("  offload: layer3=%s ipv4_checksum=%s outer_ipv4_checksum=%s tcp_checksum=%s udp_checksum=%s tunnel_vxlan=%s l2_len=%d l3_len=%d l4_len=%d outer_l2_len=%d outer_l3_len=%d",
		offload_layer3_name(plan.offload.layer3),
		bool_name(plan.offload.ipv4_checksum),
		bool_name(plan.offload.outer_ipv4_checksum),
		bool_name(plan.offload.tcp_checksum),
		bool_name(plan.offload.udp_checksum),
		bool_name(plan.offload.tunnel_vxlan),
		plan.offload.l2_len,
		plan.offload.l3_len,
		plan.offload.l4_len,
		plan.offload.outer_l2_len,
		plan.offload.outer_l3_len);
	if (plan.outer_ipv4.has_value) {
		Ipv4Fixup f = plan.outer_ipv4.value;
		io::printfn("  outer_ipv4: offset=%d header_len=%d checksum=%s", f.offset, f.header_len, fixup_mode_name(f.checksum));
	}
	if (plan.outer_ipv6.has_value) {
		Ipv6Fixup f = plan.outer_ipv6.value;
		io::printfn("  outer_ipv6: offset=%d header_len=%d", f.offset, f.header_len);
	}
	if (plan.outer_udp.has_value) {
		UdpFixup f = plan.outer_udp.value;
		io::printfn("  outer_udp: offset=%d checksum=%s", f.offset, fixup_mode_name(f.checksum));
	}
	if (plan.ipv4.has_value) {
		Ipv4Fixup f = plan.ipv4.value;
		io::printfn("  ipv4: offset=%d header_len=%d checksum=%s", f.offset, f.header_len, fixup_mode_name(f.checksum));
	}
	if (plan.ipv6.has_value) {
		Ipv6Fixup f = plan.ipv6.value;
		io::printfn("  ipv6: offset=%d header_len=%d", f.offset, f.header_len);
	}
	if (plan.udp.has_value) {
		UdpFixup f = plan.udp.value;
		io::printfn("  udp: offset=%d checksum=%s", f.offset, fixup_mode_name(f.checksum));
	}
	if (plan.tcp.has_value) {
		TcpFixup f = plan.tcp.value;
		io::printfn("  tcp: offset=%d header_len=%d checksum=%s", f.offset, f.header_len, fixup_mode_name(f.checksum));
	}
	if (plan.icmp.has_value) {
		IcmpFixup f = plan.icmp.value;
		io::printfn("  icmp: offset=%d checksum=%s", f.offset, fixup_mode_name(f.checksum));
	}
}

fn bool print_verbose_packet(String label, Packet packet, Registry* reg, generator::MaybeCount count = {}, FixupOptions fixup_options = {}) {
	PacketGenerator gen = { .registry = reg };
	PacketGenerationResult generated = gen.prepare(packet, count, fixup_options);
	foreach (w : generated.warnings) io::eprintfn("WARNING: %s", w);
	foreach (e : generated.errors) io::eprintfn("ERROR: %s", e);
	if (!generated.ok) return false;
	io::printfn("verbose packet '%s': packet_len=%d total_flows=%d planned_packets=%d",
		label, generated.packet.packet_len, generated.packet.flow_plan.total_flows, generated.packet.flow_plan.planned_packets);
	print_modifiers(generated.packet.modifiers);
	print_fixup_plan(generated.packet.fixup_plan);
	return true;
}

fn generator::MaybeCount program_packet_count(Program program) {
	generator::MaybeCount count;
	foreach (&variable : program.variables) {
		if (variable.name != "PACKET_COUNT") continue;
		ScalarValue? value = ast::evaluate(variable.expression);
		if (catch value) return count;
		if (value.kind != ScalarKind.INTEGER || value.int_val <= 0) return count;
		count.set((ulong)value.int_val);
		return count;
	}
	return count;
}

fn bool print_verbose_program(Program program, Registry* reg, FixupOptions fixup_options = {}) {
	bool ok = true;
	generator::MaybeCount count = program_packet_count(program);
	foreach (variable : program.variables) {
		ScalarValue? value = ast::evaluate(variable.expression);
		if (catch value) continue;
		if (value.kind != ScalarKind.PACKET) continue;
		generator::MaybeCount packet_count = variable.name == "PACKET" ? count : {};
		ok = print_verbose_packet(variable.name, value.packet_val, reg, packet_count, fixup_options) && ok;
	}
	return ok;
}

<* Builds the protocol registry, augmenting the predefined headers/inference
   rules with any user-defined headers loaded from `--headers <file>`. Prints
   diagnostics and fails when the header file contains errors. *>
fn Registry*? build_registry(String headers_content) {
	Registry* reg = mem::tnew(Registry, registry::create_default_registry());
	if (headers_content.len == 0) return reg;

	HeaderFileResult result = header_file::load(reg, headers_content);
	foreach (w : result.warnings) io::eprintfn("WARNING: %s", w);
	foreach (e : result.errors) io::eprintfn("ERROR: %s", e);
	if (!result.ok) return HEADER_LOAD_ERR~;
	return reg;
}

fn int run_check(String input, bool parse_only, bool verbose, Registry* reg) {
	Parser p;
	p.init(input);

	Packet? packet = p.parse_packet();
	if (catch packet) {
		io::eprintfn("parse error: %s", p.last_error_msg());
		return 1;
	}

	io::printfn("parsed packet with %d header(s)", packet.len());
	if (verbose && !print_verbose_packet("packet", packet, reg)) return 1;
	if (parse_only) return 0;

	CheckResult result = checker::checker_with_registry(reg).check(packet);
	foreach (w : result.warnings) io::eprintfn("WARNING: %s", w);
	foreach (e : result.errors) io::eprintfn("ERROR: %s", e);
	if (!result.ok) return 1;
	if (result.warnings.len()) io::eprintfn("%d warning(s) found.", result.warnings.len());
	io::printn("check ok");
	return 0;
}

fn int run_program(String input, bool parse_only, bool verbose, Registry* reg) {
	Parser p;
	p.init(input);
	Program? program = p.parse();
	if (catch program) {
		io::eprintfn("parse error: %s", p.last_error_msg());
		return 1;
	}

	io::printfn("parsed program with %d variable(s)", program.variables.len());
	if (verbose && !print_verbose_program(program, reg)) return 1;
	if (parse_only) return 0;

	Checker checker = checker::checker_with_registry(reg);
	bool ok = true;
	foreach (variable : program.variables) {
		ScalarValue? value = ast::evaluate(variable.expression);
		if (catch value) {
			io::printfn("variable %s: non-packet expression (skipped check)", variable.name);
			continue;
		}
		if (value.kind != ScalarKind.PACKET) {
			io::printfn("variable %s: non-packet expression (skipped check)", variable.name);
			continue;
		}
		CheckResult result = checker.check(value.packet_val);
		foreach (w : result.warnings) io::eprintfn("WARNING: %s", w);
		foreach (e : result.errors) io::eprintfn("ERROR: %s", e);
		ok = ok && result.ok;
	}
	return ok ? 0 : 1;
}

<* Expands the packet's flows and streams them to `output_path` as a pcap. *>
fn int run_file_mode(Packet packet, generator::MaybeCount count, String output_path, bool verbose, Registry* reg) {
	PacketGenerator gen = { .registry = reg };

	PacketGenerationResult result = gen.prepare(packet, count, {}, mem);
	foreach (w : result.warnings) io::eprintfn("WARNING: %s", w);
	foreach (e : result.errors) io::eprintfn("ERROR: %s", e);
	if (!result.ok) return 1;
	defer result.packet.free();
	if (verbose) {
		io::printfn("verbose packet 'packet': packet_len=%d total_flows=%d planned_packets=%d",
			result.packet.packet_len, result.packet.flow_plan.total_flows, result.packet.flow_plan.planned_packets);
		print_modifiers(result.packet.modifiers);
		print_fixup_plan(result.packet.fixup_plan);
	}

	File? out_file = file::open(output_path, "wb");
	if (catch out_file) {
		io::eprintfn("failed to open '%s' for writing", output_path);
		return 1;
	}
	defer (void)out_file.close();

	PcapWriter writer = { .output = &out_file };
	PcapWriteResult header = writer.write_header();
	if (!header.ok) {
		foreach (e : header.errors) io::eprintfn("ERROR: %s", e);
		return 1;
	}

	ulong planned = result.packet.flow_plan.planned_packets;
	usz packet_len = result.packet.packet_len;
	char[] payload = alloc::new_array(mem, char, (sz)packet_len);
	defer alloc::free(mem, payload.ptr);

	List{String} errors;
	errors.tinit();
	for (ulong i = 0; i < planned; i++) {
		errors.clear();
		mem::copy(payload.ptr, result.packet.base_payload.ptr, (sz)packet_len);
		if (!gen.apply_flow(&result.packet, i, payload, &errors)) {
			foreach (e : errors) io::eprintfn("ERROR: %s", e);
			return 1;
		}
		PcapWriteResult record = writer.write_packet(payload);
		if (!record.ok) {
			foreach (e : record.errors) io::eprintfn("ERROR: %s", e);
			return 1;
		}
	}

	io::printfn("wrote %d packet(s) to %s", planned, output_path);
	return 0;
}

fn int file_mode_inline(String inline_expr, generator::MaybeCount count, String output_path, bool verbose, Registry* reg) {
	String expr = inline_expr;
	if (expr.starts_with("PACKET:")) expr = expr["PACKET:".len..].trim();

	Parser p;
	p.init(expr);
	Packet? packet = p.parse_packet();
	if (catch packet) {
		io::eprintfn("parse error: %s", p.last_error_msg());
		return 1;
	}
	return run_file_mode(packet, count, output_path, verbose, reg);
}

fn int file_mode_file(String content, generator::MaybeCount cli_count, String output_path, bool verbose, Registry* reg) {
	Parser p;
	p.init(content);

	if (content.contains("PACKET:")) {
		Program? program = p.parse();
		if (catch program) {
			io::eprintfn("parse error: %s", p.last_error_msg());
			return 1;
		}
		FileProgram parsed = file_program::parse(program, cli_count);
		foreach (w : parsed.warnings) io::eprintfn("WARNING: %s", w);
		foreach (e : parsed.errors) io::eprintfn("ERROR: %s", e);
		if (!parsed.ok) return 1;
		return run_file_mode(parsed.packet, parsed.packet_count, output_path, verbose, reg);
	}

	Packet? packet = p.parse_packet();
	if (catch packet) {
		io::eprintfn("parse error: %s", p.last_error_msg());
		return 1;
	}
	return run_file_mode(packet, cli_count, output_path, verbose, reg);
}

<* DPDK-free validation of a runtime program (mirrors Runtime.check). *>
fn int run_runtime_check(String content, RunOptions options, bool verbose, Registry* reg) {
	Parser p;
	p.init(content);
	Program? program = p.parse();
	if (catch program) {
		io::eprintfn("parse error: %s", p.last_error_msg());
		return 1;
	}
	if (verbose && !print_verbose_program(program, reg, runtime::live_fixup_options())) return 1;

	Runtime rt = runtime::runtime_with_registry(reg);
	Result result = rt.check(program, options);
	foreach (w : result.warnings) io::eprintfn("WARNING: %s", w);
	foreach (e : result.errors) io::eprintfn("ERROR: %s", e);
	if (!result.ok) return 1;
	io::printfn("check ok; planned %d of %d flow(s), packet_len %d bytes, pmd_threads %d, rx_threads %d, tx_batch_size %d, planned_transmissions_per_cycle %d",
		result.planned_packets, result.total_flows, result.packet_len,
		result.pmd_threads, result.rx_threads, result.tx_batch_size, result.planned_transmissions);
	return 0;
}

<* Live DPDK mode: parses a runtime program (with DPDK_ARGS) and transmits or
   captures traffic via the EAL-backed runtime. Requires root / TAP access. *>
fn int run_live_mode(String content, String program_name, RunOptions options, bool verbose, Registry* reg) {
	Parser p;
	p.init(content);
	Program? program = p.parse();
	if (catch program) {
		io::eprintfn("parse error: %s", p.last_error_msg());
		return 1;
	}
	if (verbose && !print_verbose_program(program, reg, runtime::live_fixup_options())) return 1;

	Runtime rt = runtime::runtime_with_registry(reg);
	Result result = rt.run(program, program_name, options);
	foreach (w : result.warnings) io::eprintfn("WARNING: %s", w);
	foreach (e : result.errors) io::eprintfn("ERROR: %s", e);
	if (!result.ok) return 1;

	if (options.capture) {
		io::printfn("Capture completed; rte_eal_init parsed %d argument(s), port %d received %d packet(s), %d byte(s), missed %d, errors %d",
			result.eal_parsed_args, result.port_id, result.rx_received, result.rx_bytes, result.rx_missed, result.rx_errors);
		if (options.capture_file.has_value) {
			io::printfn("Capture written to '%s' with %d packet(s)", options.capture_file.value, result.rx_received);
		}
		return 0;
	}

	io::printfn("DPDK runtime completed; rte_eal_init parsed %d argument(s), port %d sent %d/%d packet(s), planned %d of %d flow(s), packet_len %d bytes, pmd_threads %d, rx_threads %d, tx_batch_size %d, clone_count %d, split %s, once %s, planned_transmissions_per_cycle %d",
		result.eal_parsed_args, result.port_id, result.tx_sent, result.tx_attempted,
		result.planned_packets, result.total_flows, result.packet_len,
		result.pmd_threads, result.rx_threads, result.tx_batch_size, result.clone_count,
		result.split ? "on" : "off", result.once ? "on" : "off", result.planned_transmissions);
	foreach (worker : result.workers) {
		io::printfn("PMD worker %d lcore %d queue %d flows %d+%d sent %d/%d packet(s)",
			worker.worker_id, worker.lcore_id, worker.queue_id, worker.first_flow, worker.flow_count, worker.tx_sent, worker.tx_attempted);
	}
	foreach (rx : result.rx_workers) {
		io::printfn("RX worker %d lcore %d queue %d received %d bytes %d",
			rx.worker_id, rx.lcore_id, rx.queue_id, rx.rx_received, rx.rx_bytes);
	}
	if (result.rx_threads > 0) {
		io::printfn("RX aggregate: received %d bytes %d missed %d errors %d",
			result.rx_received, result.rx_bytes, result.rx_missed, result.rx_errors);
	}
	return 0;
}

fn int main(String[] args) {
	if (args.len < 2) return usage(args[0]);

	bool parse_only = false;
	String input_path = "";
	String inline_expr = "";
	bool use_inline = false;
	String output_path = "";
	String headers_path = "";
	generator::MaybeCount cli_count;
	bool verbose = false;

	RunOptions live_options = runtime::default_run_options();
	bool live_flag_present = false;
	bool check_only = false;

	for (usz i = 1; i < args.len; i++) {
		if (args[i] == "--parse-only") {
			parse_only = true;
		}
		else if (args[i] == "--check") {
			check_only = true;
		}
		else if (args[i] == "-v" || args[i] == "--verbose") {
			verbose = true;
		}
		else if (args[i] == "--headers") {
			if (i + 1 >= args.len) return usage(args[0]);
			headers_path = args[++i];
		}
		else if (args[i] == "-e") {
			if (i + 1 >= args.len) return usage(args[0]);
			use_inline = true;
			inline_expr = args[++i];
		}
		else if (args[i] == "-w" || args[i] == "--write") {
			if (i + 1 >= args.len) return usage(args[0]);
			output_path = args[++i];
		}
		else if (args[i] == "-c" || args[i] == "--count") {
			if (i + 1 >= args.len) return usage(args[0]);
			long? value = args[++i].to_long();
			if (catch value) {
				io::eprintfn("invalid count '%s'", args[i]);
				return 1;
			}
			if (value <= 0) {
				io::eprintfn("count must be positive");
				return 1;
			}
			cli_count.set((ulong)value);
		}
		else if (args[i] == "--clone") {
			if (i + 1 >= args.len) return usage(args[0]);
			long? value = args[++i].to_long();
			if (catch value) {
				io::eprintfn("clone count must be a positive integer");
				return 1;
			}
			if (value <= 0) {
				io::eprintfn("clone count must be a positive integer");
				return 1;
			}
			live_options.clone_count = (ulong)value;
			live_flag_present = true;
		}
		else if (args[i] == "--split") {
			live_options.split = true;
			live_flag_present = true;
		}
		else if (args[i] == "--once") {
			live_options.once = true;
			live_flag_present = true;
		}
		else if (args[i] == "--stats-interval") {
			if (i + 1 >= args.len) return usage(args[0]);
			long? value = args[++i].to_long();
			if (catch value) {
				io::eprintfn("stats interval must be a positive integer");
				return 1;
			}
			if (value <= 0) {
				io::eprintfn("stats interval must be a positive integer");
				return 1;
			}
			live_options.stats_interval_seconds.set((ulong)value);
			live_flag_present = true;
		}
		else if (args[i] == "--capture") {
			live_options.capture = true;
			live_flag_present = true;
			if (i + 1 < args.len && !args[i + 1].starts_with("-")) {
				live_options.capture_file.set(args[++i]);
			}
		}
		else if (args[i].starts_with("-")) {
			return usage(args[0]);
		}
		else {
			input_path = args[i];
		}
	}

	String headers_content = "";
	if (headers_path.len) {
		char[]? hdr_bytes = file::load(tmem, headers_path);
		if (catch hdr_bytes) {
			io::eprintfn("failed to read '%s'", headers_path);
			return 1;
		}
		headers_content = (String)hdr_bytes;
	}

	Registry*? reg = build_registry(headers_content);
	if (catch reg) return 1;

	if (output_path.len) {
		if (use_inline) return file_mode_inline(inline_expr, cli_count, output_path, verbose, reg);
		if (!input_path.len) return usage(args[0]);
		char[]? bytes = file::load(tmem, input_path);
		if (catch bytes) {
			io::eprintfn("failed to read '%s'", input_path);
			return 1;
		}
		return file_mode_file((String)bytes, cli_count, output_path, verbose, reg);
	}

	if (use_inline) {
		String expr = inline_expr;
		if (expr.starts_with("PACKET:")) expr = expr["PACKET:".len..].trim();
		return run_check(expr, parse_only, verbose, reg);
	}

	if (!input_path.len) return usage(args[0]);

	char[]? bytes = file::load(tmem, input_path);
	if (catch bytes) {
		io::eprintfn("failed to read '%s'", input_path);
		return 1;
	}
	String content = (String)bytes;

	// `--check` validates a runtime program (DPDK-free) without touching the EAL.
	if (check_only) {
		return run_runtime_check(content, live_options, verbose, reg);
	}

	// Live DPDK mode: a runtime program declares DPDK_ARGS. Unless the user only
	// asked to parse/check, drive the EAL-backed runtime (TX or capture).
	if (!parse_only && (live_options.capture || content.contains("DPDK_ARGS:"))) {
		return run_live_mode(content, args[0], live_options, verbose, reg);
	}
	if (live_flag_present) {
		io::eprintfn("live options require a runtime program with a DPDK_ARGS variable");
		return usage(args[0]);
	}

	if (content.contains("PACKET:")) {
		return run_program(content, parse_only, verbose, reg);
	}
	return run_check(content, parse_only, verbose, reg);
}

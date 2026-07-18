module flowforge;
import flowforge::ast;
import flowforge::parser;
import flowforge::checker;
import flowforge::generator;
import flowforge::pcap;
import flowforge::registry;
import std::collections::list;
import std::io;
import std::io::file;

faultdef NO_PACKET;

fn int usage(String prog) {
	io::eprintfn("Usage: %s [--parse-only] <program.packet>", prog);
	io::eprintfn("       %s [--parse-only] -e '<packet expression>'", prog);
	io::eprintfn("       %s -w <out.pcap> [-c <count>] <program.packet>", prog);
	io::eprintfn("       %s -w <out.pcap> [-c <count>] -e '<packet expression>'", prog);
	return 1;
}

fn int run_check(String input, bool parse_only) {
	Parser p;
	p.init(input);

	Packet? packet = p.parse_packet();
	if (catch packet) {
		io::eprintfn("parse error: %s", p.last_error_msg());
		return 1;
	}

	io::printfn("parsed packet with %d header(s)", packet.len);
	if (parse_only) return 0;

	CheckResult result = checker::checker_with_default().check(packet);
	foreach (w : result.warnings) io::eprintfn("WARNING: %s", w);
	foreach (e : result.errors) io::eprintfn("ERROR: %s", e);
	if (!result.ok) return 1;
	if (result.warnings.len) io::eprintfn("%d warning(s) found.", result.warnings.len);
	io::printn("check ok");
	return 0;
}

fn int run_program(String input, bool parse_only) {
	Parser p;
	p.init(input);
	Program? program = p.parse();
	if (catch program) {
		io::eprintfn("parse error: %s", p.last_error_msg());
		return 1;
	}

	io::printfn("parsed program with %d variable(s)", program.variables.len);
	if (parse_only) return 0;

	Checker checker = checker::checker_with_default();
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

<* Finds the `PACKET:` variable in a program and evaluates it to a packet. *>
fn Packet? program_packet(Program program) {
	foreach (variable : program.variables) {
		if (variable.name != "PACKET") continue;
		ScalarValue? value = ast::evaluate(variable.expression);
		if (catch value) return NO_PACKET~;
		if (value.kind != ScalarKind.PACKET) return NO_PACKET~;
		return value.packet_val;
	}
	return NO_PACKET~;
}

<* Reads the optional `PACKET_COUNT:` variable from a program. *>
fn generator::MaybeCount program_packet_count(Program program) {
	generator::MaybeCount count;
	foreach (variable : program.variables) {
		if (variable.name != "PACKET_COUNT") continue;
		ScalarValue? value = ast::evaluate(variable.expression);
		if (catch value) continue;
		if (value.kind == ScalarKind.INTEGER && value.int_val > 0) {
			count.set((ulong)value.int_val);
		}
	}
	return count;
}

<* Expands the packet's flows and streams them to `output_path` as a pcap. *>
fn int run_file_mode(Packet packet, generator::MaybeCount count, String output_path) {
	Registry reg = registry::create_default_registry();
	PacketGenerator gen = { .registry = &reg };

	PacketGenerationResult result = gen.prepare(packet, count, {}, mem);
	foreach (w : result.warnings) io::eprintfn("WARNING: %s", w);
	foreach (e : result.errors) io::eprintfn("ERROR: %s", e);
	if (!result.ok) return 1;
	defer result.packet.free();

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

fn int file_mode_inline(String inline_expr, generator::MaybeCount count, String output_path) {
	String expr = inline_expr;
	if (expr.starts_with("PACKET:")) expr = expr["PACKET:".len..].trim();

	Parser p;
	p.init(expr);
	Packet? packet = p.parse_packet();
	if (catch packet) {
		io::eprintfn("parse error: %s", p.last_error_msg());
		return 1;
	}
	return run_file_mode(packet, count, output_path);
}

fn int file_mode_file(String content, generator::MaybeCount cli_count, String output_path) {
	Parser p;
	p.init(content);

	if (content.contains("PACKET:")) {
		Program? program = p.parse();
		if (catch program) {
			io::eprintfn("parse error: %s", p.last_error_msg());
			return 1;
		}
		Packet? packet = program_packet(program);
		if (catch packet) {
			io::eprintfn("program has no packet-valued PACKET variable");
			return 1;
		}
		generator::MaybeCount count = cli_count.has_value ? cli_count : program_packet_count(program);
		return run_file_mode(packet, count, output_path);
	}

	Packet? packet = p.parse_packet();
	if (catch packet) {
		io::eprintfn("parse error: %s", p.last_error_msg());
		return 1;
	}
	return run_file_mode(packet, cli_count, output_path);
}

fn int main(String[] args) {
	if (args.len < 2) return usage(args[0]);

	bool parse_only = false;
	String input_path = "";
	String inline_expr = "";
	bool use_inline = false;
	String output_path = "";
	generator::MaybeCount cli_count;

	for (usz i = 1; i < args.len; i++) {
		if (args[i] == "--parse-only") {
			parse_only = true;
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
		else if (args[i].starts_with("-")) {
			return usage(args[0]);
		}
		else {
			input_path = args[i];
		}
	}

	if (output_path.len) {
		if (use_inline) return file_mode_inline(inline_expr, cli_count, output_path);
		if (!input_path.len) return usage(args[0]);
		char[]? bytes = file::load(tmem, input_path);
		if (catch bytes) {
			io::eprintfn("failed to read '%s'", input_path);
			return 1;
		}
		return file_mode_file((String)bytes, cli_count, output_path);
	}

	if (use_inline) {
		String expr = inline_expr;
		if (expr.starts_with("PACKET:")) expr = expr["PACKET:".len..].trim();
		return run_check(expr, parse_only);
	}

	if (!input_path.len) return usage(args[0]);

	char[]? bytes = file::load(tmem, input_path);
	if (catch bytes) {
		io::eprintfn("failed to read '%s'", input_path);
		return 1;
	}
	String content = (String)bytes;
	if (content.contains("PACKET:") && content.contains_char(':')) {
		return run_program(content, parse_only);
	}
	return run_check(content, parse_only);
}

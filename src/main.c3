module flowforge;
import flowforge::ast;
import flowforge::parser;
import flowforge::checker;
import std::io;
import std::io::file;

fn int usage(String prog) {
	io::eprintfn("Usage: %s [--parse-only] <program.packet>", prog);
	io::eprintfn("       %s [--parse-only] -e '<packet expression>'", prog);
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

fn int main(String[] args) {
	if (args.len < 2) return usage(args[0]);

	bool parse_only = false;
	String input_path = "";
	String inline_expr = "";
	bool use_inline = false;

	for (usz i = 1; i < args.len; i++) {
		if (args[i] == "--parse-only") {
			parse_only = true;
		}
		else if (args[i] == "-e") {
			if (i + 1 >= args.len) return usage(args[0]);
			use_inline = true;
			inline_expr = args[++i];
		}
		else if (args[i].starts_with("-")) {
			return usage(args[0]);
		}
		else {
			input_path = args[i];
		}
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

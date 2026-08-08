module flowforge::testutil;
import flowforge::parser;
import flowforge::ast;
import std::collections::result;

fn Packet must_parse(String input) {
	Parser p;
	p.init(input);
	Result{Packet, String} pkt = p.parse_packet();
	if (!pkt.is_ok) unreachable();
	return pkt.value;
}

fn Program must_parse_program(String input) {
	Parser p;
	p.init(input);
	Result{Program, String} program = p.parse();
	if (!program.is_ok) unreachable();
	return program.value;
}

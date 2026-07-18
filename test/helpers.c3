module flowforge::testutil;
import flowforge::parser;
import flowforge::ast;

fn Packet must_parse(String input) {
	Parser p;
	p.init(input);
	Packet? pkt = p.parse_packet();
	if (catch pkt) unreachable();
	return pkt;
}

fn Program must_parse_program(String input) {
	Parser p;
	p.init(input);
	Program? program = p.parse();
	if (catch program) unreachable();
	return program;
}

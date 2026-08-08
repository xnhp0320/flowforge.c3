module flowforge::testutil;
import flowforge::parser;
import flowforge::ast;
import std::collections::result;

fn Packet must_parse(String input) {
	Parser p;
	p.init(input);
	return p.parse_packet().ok()!!;
}

fn Program must_parse_program(String input) {
	Parser p;
	p.init(input);
	return p.parse().ok()!!;
}

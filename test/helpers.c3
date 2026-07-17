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

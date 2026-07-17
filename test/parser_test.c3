module flowforge_parser_test @test;
import flowforge::token;
import flowforge::lexer;
import flowforge::parser;
import flowforge::ast;

fn void test_parser_single_header_no_attrs() @test {
	Parser p;
	p.init("Ether");
	Packet? pkt = p.parse_packet();
	if (catch pkt) unreachable();
	assert(pkt.len == 1);
	assert(pkt[0].protocol == "Ether");
	assert(pkt[0].attributes.len == 0);
}

fn void test_parser_single_header_with_attrs() @test {
	Parser p;
	p.init("Ether(dst=\"ff:ff:ff:ff:ff:ff\",src=\"00:11:22:33:44:55\")");
	Packet? pkt = p.parse_packet();
	if (catch pkt) unreachable();
	assert(pkt.len == 1);
	assert(pkt[0].protocol == "Ether");
	assert(pkt[0].attributes.len == 2);

	Attribute a0 = pkt[0].attributes[0];
	assert(a0.name == "dst");
	assert(a0.has_value);
	ScalarValue? a0_value = ast::attr_scalar(&a0);
	if (catch a0_value) unreachable();
	assert(a0_value.kind == ScalarKind.STRING);
	assert(a0_value.string_val == "ff:ff:ff:ff:ff:ff");

	Attribute a1 = pkt[0].attributes[1];
	assert(a1.name == "src");
	assert(a1.has_value);
	ScalarValue? a1_value = ast::attr_scalar(&a1);
	if (catch a1_value) unreachable();
	assert(a1_value.kind == ScalarKind.STRING);
	assert(a1_value.string_val == "00:11:22:33:44:55");
}

fn void test_parser_scapy_style() @test {
	Parser p;
	p.init("Ether(dst=\"ff:ff:ff:ff:ff:ff\")/IP(src=\"192.168.1.1\",dst=\"10.0.0.1\")/TCP(dport=80)");
	Packet? pkt = p.parse_packet();
	if (catch pkt) unreachable();
	assert(pkt.len == 3);

	assert(pkt[0].protocol == "Ether");
	assert(pkt[0].attributes.len == 1);
	assert(pkt[0].attributes[0].name == "dst");
	ScalarValue? v0 = ast::attr_scalar(&pkt[0].attributes[0]);
	if (catch v0) { assert(false); }
	assert(v0.string_val == "ff:ff:ff:ff:ff:ff");

	assert(pkt[1].protocol == "IP");
	assert(pkt[1].attributes.len == 2);
	assert(pkt[1].attributes[0].name == "src");
	ScalarValue? v1 = ast::attr_scalar(&pkt[1].attributes[0]);
	if (catch v1) { assert(false); }
	assert(v1.string_val == "192.168.1.1");
	assert(pkt[1].attributes[1].name == "dst");
	ScalarValue? v2 = ast::attr_scalar(&pkt[1].attributes[1]);
	if (catch v2) { assert(false); }
	assert(v2.string_val == "10.0.0.1");

	assert(pkt[2].protocol == "TCP");
	assert(pkt[2].attributes.len == 1);
	assert(pkt[2].attributes[0].name == "dport");
	ScalarValue? v3 = ast::attr_scalar(&pkt[2].attributes[0]);
	if (catch v3) { assert(false); }
	assert(v3.kind == ScalarKind.INTEGER);
	assert(v3.int_val == 80);
}

fn void test_parser_hex_number() @test {
	Parser p;
	p.init("Raw(len=0xFF)");
	Packet? pkt = p.parse_packet();
	if (catch pkt) unreachable();
	assert(pkt.len == 1);
	ScalarValue? val = ast::attr_scalar(&pkt[0].attributes[0]);
	if (catch val) { assert(false); }
	assert(val.kind == ScalarKind.INTEGER);
	assert(val.int_val == 255);
}

fn void test_parser_binary_number() @test {
	Parser p;
	p.init("Raw(len=0b101010)");
	Packet? pkt = p.parse_packet();
	if (catch pkt) unreachable();
	assert(pkt.len == 1);
	ScalarValue? val = ast::attr_scalar(&pkt[0].attributes[0]);
	if (catch val) { assert(false); }
	assert(val.kind == ScalarKind.INTEGER);
	assert(val.int_val == 42);
}

fn void test_parser_string_escape() @test {
	Parser p;
	p.init("Raw(data=\"line1\\nline2\\ttabbed\")");
	Packet? pkt = p.parse_packet();
	if (catch pkt) unreachable();
	assert(pkt.len == 1);
	ScalarValue? val = ast::attr_scalar(&pkt[0].attributes[0]);
	if (catch val) { assert(false); }
	assert(val.kind == ScalarKind.STRING);
	assert(val.string_val == "line1\nline2\ttabbed");
}

fn void test_parser_attribute_name_only() @test {
	Parser p;
	p.init("Flag(URG,ACK,PSH)");
	Packet? pkt = p.parse_packet();
	if (catch pkt) unreachable();
	assert(pkt.len == 1);
	assert(pkt[0].attributes.len == 3);
	assert(pkt[0].attributes[0].name == "URG");
	assert(!pkt[0].attributes[0].has_value);
	assert(pkt[0].attributes[1].name == "ACK");
	assert(!pkt[0].attributes[1].has_value);
	assert(pkt[0].attributes[2].name == "PSH");
	assert(!pkt[0].attributes[2].has_value);
}

fn void test_parser_empty_parens() @test {
	Parser p;
	p.init("Ether()");
	Packet? pkt = p.parse_packet();
	if (catch pkt) unreachable();
	assert(pkt.len == 1);
	assert(pkt[0].protocol == "Ether");
	assert(pkt[0].attributes.len == 0);
}

fn void test_parser_packet_variable_wrapper() @test {
	Parser p;
	p.init("PACKET: Ether(dst=\"ff:ff:ff:ff:ff:ff\")/IP(src=\"192.168.1.1\")");
	Program? program = p.parse();
	if (catch program) unreachable();
	assert(program.variables.len == 1);
	assert(program.variables[0].name == "PACKET");

	ScalarValue? value = ast::evaluate(program.variables[0].expression);
	if (catch value) unreachable();
	assert(value.kind == ScalarKind.PACKET);
	Packet pkt = value.packet_val;
	assert(pkt.len == 2);
	assert(pkt[0].protocol == "Ether");
	assert(pkt[1].protocol == "IP");
}

fn void test_parser_string_expression() @test {
	Parser p;
	p.init("\"hello\"");
	Expression? expression = p.parse_expression();
	if (catch expression) unreachable();

	ScalarValue? value = ast::evaluate(expression);
	if (catch value) unreachable();
	assert(value.kind == ScalarKind.STRING);
	assert(value.string_val == "hello");
}

fn void test_parser_integer_expression() @test {
	Parser p;
	p.init("42");
	Expression? expression = p.parse_expression();
	if (catch expression) unreachable();

	ScalarValue? value = ast::evaluate(expression);
	if (catch value) unreachable();
	assert(value.kind == ScalarKind.INTEGER);
	assert(value.int_val == 42);
}

fn void test_parser_packet_expression() @test {
	Parser p;
	p.init("Ether()/TCP(dport=80)");
	Expression? expression = p.parse_expression();
	if (catch expression) unreachable();

	ScalarValue? value = ast::evaluate(expression);
	if (catch value) unreachable();
	assert(value.kind == ScalarKind.PACKET);
	Packet pkt = value.packet_val;
	assert(pkt.len == 2);
	assert(pkt[0].protocol == "Ether");
	assert(pkt[1].protocol == "TCP");
}

fn void test_parser_attribute_can_take_packet_expression() @test {
	Parser p;
	p.init("HeaderA(X=HeaderB()/HeaderC(),D=1)");
	Packet? pkt = p.parse_packet();
	if (catch pkt) unreachable();
	assert(pkt.len == 1);
	assert(pkt[0].attributes.len == 2);

	ScalarValue? x_value = ast::attr_scalar(&pkt[0].attributes[0]);
	if (catch x_value) { assert(false); }
	assert(x_value.kind == ScalarKind.PACKET);
	Packet nested = x_value.packet_val;
	assert(nested.len == 2);
	assert(nested[0].protocol == "HeaderB");
	assert(nested[1].protocol == "HeaderC");

	ScalarValue? d_value = ast::attr_scalar(&pkt[0].attributes[1]);
	if (catch d_value) { assert(false); }
	assert(d_value.kind == ScalarKind.INTEGER);
	assert(d_value.int_val == 1);
}

fn void test_parser_variable_definition() @test {
	Parser p;
	p.init("XXX: 1");
	Variable? variable = p.parse_variable();
	if (catch variable) unreachable();
	assert(variable.name == "XXX");

	ScalarValue? value = ast::evaluate(variable.expression);
	if (catch value) unreachable();
	assert(value.kind == ScalarKind.INTEGER);
	assert(value.int_val == 1);
}

fn void test_parser_program_with_variables() @test {
	Parser p;
	p.init("XXX: 1\nPACKET: IP(src=\"192.168.0.1\")/TCP(dport=80)");
	Program? program = p.parse();
	if (catch program) unreachable();
	assert(program.variables.len == 2);
	assert(program.variables[0].name == "XXX");
	assert(program.variables[1].name == "PACKET");

	ScalarValue? packet_value = ast::evaluate(program.variables[1].expression);
	if (catch packet_value) unreachable();
	assert(packet_value.kind == ScalarKind.PACKET);
	Packet pkt = packet_value.packet_val;
	assert(pkt.len == 2);
	assert(pkt[0].protocol == "IP");
	ScalarValue? src = ast::attr_scalar(&pkt[0].attributes[0]);
	if (catch src) unreachable();
	assert(src.string_val == "192.168.0.1");
}

fn void test_parser_invalid_input() @test {
	Parser p;
	p.init("Ether(dst=\"unclosed)");
	if (catch p.parse_packet()) {
		assert(p.last_error_msg().len > 0);
	}
	else { unreachable(); }
}

fn void test_parser_operator_slash() @test {
	Packet pkt = {
		{
			.protocol = "Ether",
			.attributes = {
				{ .name = "dst", .has_value = true, .value = ast::expr_string("ff:ff:ff:ff:ff:ff") }
			}
		},
		{
			.protocol = "IP",
			.attributes = {
				{ .name = "src", .has_value = true, .value = ast::expr_string("192.168.1.1") }
			}
		},
	};
	assert(pkt.len == 2);
	assert(pkt[0].protocol == "Ether");
	assert(pkt[1].protocol == "IP");

	Packet pkt2 = {
		pkt[0],
		pkt[1],
		{
			.protocol = "TCP",
			.attributes = {
				{ .name = "dport", .has_value = true, .value = ast::expr_integer(80) }
			}
		},
	};
	assert(pkt2.len == 3);
	assert(pkt2[2].protocol == "TCP");
	ScalarValue? dport = ast::attr_scalar(&pkt2[2].attributes[0]);
	if (catch dport) unreachable();
	assert(dport.kind == ScalarKind.INTEGER);
	assert(dport.int_val == 80);
}

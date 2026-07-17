module flowforge_test @test;
import flowforge::token;
import flowforge::lexer;
import flowforge::parser;
import flowforge::ast;
import flowforge::checker;

fn void test_lexer_identifiers() @test {
	Lexer lexer;
	lexer.init("Ether IP_Header dst23 _underscore");
	Token t = lexer.next()!!;
	assert(t.type == TokenType.IDENTIFIER);
	assert(t.lexeme == "Ether");
	t = lexer.next()!!;
	assert(t.type == TokenType.IDENTIFIER);
	assert(t.lexeme == "IP_Header");
	t = lexer.next()!!;
	assert(t.lexeme == "dst23");
	t = lexer.next()!!;
	assert(t.lexeme == "_underscore");
	t = lexer.next()!!;
	assert(t.type == TokenType.END_OF_FILE);
}

fn void test_lexer_unterminated_string() @test {
	Lexer lexer;
	lexer.init("\"hello");
	if (catch lexer.next()) {
		assert(lexer.last_error_msg() == "unterminated string literal");
	}
	else { assert(false); }
}

fn void test_parser_scapy_style() @test {
	Parser p;
	p.init("Ether(dst=\"ff:ff:ff:ff:ff:ff\")/IP(src=\"192.168.1.1\",dst=\"10.0.0.1\")/TCP(dport=80)");
	Packet pkt = p.parse_packet()!!;
	assert(pkt.len == 3);
	assert(pkt[0].protocol == "Ether");
	assert(pkt[1].protocol == "IP");
	assert(pkt[2].protocol == "TCP");
	ScalarValue sport = ast::attr_scalar(&pkt[2].attributes[0])!!;
	assert(sport.kind == ScalarKind.INTEGER);
	assert(sport.int_val == 80);
}

fn void test_parser_hex_and_binary() @test {
	Parser p;
	p.init("Raw(len=0xFF)");
	Packet pkt = p.parse_packet()!!;
	ScalarValue val = ast::attr_scalar(&pkt[0].attributes[0])!!;
	assert(val.int_val == 255);

	p.init("Raw(len=0b101010)");
	pkt = p.parse_packet()!!;
	val = ast::attr_scalar(&pkt[0].attributes[0])!!;
	assert(val.int_val == 42);
}

fn void test_parser_invalid() @test {
	Parser p;
	p.init("Ether(dst=\"unclosed)");
	if (catch p.parse_packet()) {
		assert(p.last_error_msg().len > 0);
	}
	else { assert(false); }
}

fn void test_checker_unknown_header() @test {
	Parser p;
	p.init("Ether()/BadProtocol()");
	Packet pkt = p.parse_packet()!!;
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("BadProtocol"));
}

fn void test_checker_scapy_style() @test {
	Parser p;
	p.init("Ether(dst=\"ff:ff:ff:ff:ff:ff\")/IP(src=\"192.168.1.1\",dst=\"10.0.0.1\")/TCP(dport=80,sport=1234)");
	Packet pkt = p.parse_packet()!!;
	CheckResult result = checker::checker_with_default().check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
	assert(result.warnings.len == 0);
}

fn void test_checker_unknown_attr_warning() @test {
	Parser p;
	p.init("Ether(dst=\"ff:ff:ff:ff:ff:ff\",foobar=42)");
	Packet pkt = p.parse_packet()!!;
	CheckResult result = checker::checker_with_default().check(pkt);
	assert(result.ok);
	assert(result.warnings.len == 1);
	assert(result.warnings[0].contains("foobar"));
}

fn void test_program_variables() @test {
	Parser p;
	p.init("XXX: 1\nPACKET: IP(src=\"192.168.0.1\")/TCP(dport=80)");
	Program prog = p.parse()!!;
	assert(prog.variables.len == 2);
	assert(prog.variables[0].name == "XXX");
	assert(prog.variables[1].name == "PACKET");
}

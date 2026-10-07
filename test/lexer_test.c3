module flowforge_lexer_test @test;
import flowforge::token;
import std::collections::result;
import flowforge::lexer;

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
	assert(t.type == TokenType.IDENTIFIER);
	assert(t.lexeme == "dst23");

	t = lexer.next()!!;
	assert(t.type == TokenType.IDENTIFIER);
	assert(t.lexeme == "_underscore");

	t = lexer.next()!!;
	assert(t.type == TokenType.END_OF_FILE);
}

fn void test_lexer_symbols() @test {
	Lexer lexer;
	lexer.init("= ( ) , / :");

	Token t = lexer.next()!!;
	assert(t.type == TokenType.EQUAL);

	t = lexer.next()!!;
	assert(t.type == TokenType.LEFT_PAREN);

	t = lexer.next()!!;
	assert(t.type == TokenType.RIGHT_PAREN);

	t = lexer.next()!!;
	assert(t.type == TokenType.COMMA);

	t = lexer.next()!!;
	assert(t.type == TokenType.SLASH);

	t = lexer.next()!!;
	assert(t.type == TokenType.COLON);

	t = lexer.next()!!;
	assert(t.type == TokenType.END_OF_FILE);
}

fn void test_lexer_strings() @test {
	Lexer lexer;
	lexer.init("\"hello\" \"world\" \"\"");

	Token t = lexer.next()!!;
	assert(t.type == TokenType.STRING_LITERAL);
	assert(t.lexeme == "\"hello\"");

	t = lexer.next()!!;
	assert(t.type == TokenType.STRING_LITERAL);
	assert(t.lexeme == "\"world\"");

	t = lexer.next()!!;
	assert(t.type == TokenType.STRING_LITERAL);
	assert(t.lexeme == "\"\"");

	t = lexer.next()!!;
	assert(t.type == TokenType.END_OF_FILE);
}

fn void test_lexer_string_escape() @test {
	Lexer lexer;
	lexer.init("\"hello\\nworld\"");

	Token t = lexer.next()!!;
	assert(t.type == TokenType.STRING_LITERAL);
	assert(t.lexeme == "\"hello\\nworld\"");
}

fn void test_lexer_numbers() @test {
	Lexer lexer;
	lexer.init("123 0 0xFF 0xab 0x0 0b1010 0B11");

	Token t = lexer.next()!!;
	assert(t.type == TokenType.INTEGER_LITERAL);
	assert(t.lexeme == "123");

	t = lexer.next()!!;
	assert(t.type == TokenType.INTEGER_LITERAL);
	assert(t.lexeme == "0");

	t = lexer.next()!!;
	assert(t.type == TokenType.INTEGER_LITERAL);
	assert(t.lexeme == "0xFF");

	t = lexer.next()!!;
	assert(t.type == TokenType.INTEGER_LITERAL);
	assert(t.lexeme == "0xab");

	t = lexer.next()!!;
	assert(t.type == TokenType.INTEGER_LITERAL);
	assert(t.lexeme == "0x0");

	t = lexer.next()!!;
	assert(t.type == TokenType.INTEGER_LITERAL);
	assert(t.lexeme == "0b1010");

	t = lexer.next()!!;
	assert(t.type == TokenType.INTEGER_LITERAL);
	assert(t.lexeme == "0B11");

	t = lexer.next()!!;
	assert(t.type == TokenType.END_OF_FILE);
}

fn void test_lexer_scapy_style() @test {
	Lexer lexer;
	lexer.init("Ether(dst=\"ff:ff:ff:ff:ff:ff\")/IP(src=\"192.168.1.1\",dst=\"10.0.0.1\")/TCP(dport=80)");

	Token t = lexer.next()!!;
	assert(t.type == TokenType.IDENTIFIER);
	assert(t.lexeme == "Ether");

	t = lexer.next()!!;
	assert(t.type == TokenType.LEFT_PAREN);

	t = lexer.next()!!;
	assert(t.type == TokenType.IDENTIFIER);
	assert(t.lexeme == "dst");

	t = lexer.next()!!;
	assert(t.type == TokenType.EQUAL);

	t = lexer.next()!!;
	assert(t.type == TokenType.STRING_LITERAL);
	assert(t.lexeme == "\"ff:ff:ff:ff:ff:ff\"");

	t = lexer.next()!!;
	assert(t.type == TokenType.RIGHT_PAREN);

	t = lexer.next()!!;
	assert(t.type == TokenType.SLASH);

	t = lexer.next()!!;
	assert(t.type == TokenType.IDENTIFIER);
	assert(t.lexeme == "IP");

	t = lexer.next()!!;
	assert(t.type == TokenType.LEFT_PAREN);

	t = lexer.next()!!;
	assert(t.type == TokenType.IDENTIFIER);
	assert(t.lexeme == "src");

	t = lexer.next()!!;
	assert(t.type == TokenType.EQUAL);

	t = lexer.next()!!;
	assert(t.type == TokenType.STRING_LITERAL);

	t = lexer.next()!!;
	assert(t.type == TokenType.COMMA);

	t = lexer.next()!!;
	assert(t.type == TokenType.IDENTIFIER);
	assert(t.lexeme == "dst");

	t = lexer.next()!!;
	assert(t.type == TokenType.EQUAL);

	t = lexer.next()!!;
	assert(t.type == TokenType.STRING_LITERAL);

	t = lexer.next()!!;
	assert(t.type == TokenType.RIGHT_PAREN);

	t = lexer.next()!!;
	assert(t.type == TokenType.SLASH);

	t = lexer.next()!!;
	assert(t.type == TokenType.IDENTIFIER);
	assert(t.lexeme == "TCP");

	t = lexer.next()!!;
	assert(t.type == TokenType.LEFT_PAREN);

	t = lexer.next()!!;
	assert(t.type == TokenType.IDENTIFIER);
	assert(t.lexeme == "dport");

	t = lexer.next()!!;
	assert(t.type == TokenType.EQUAL);

	t = lexer.next()!!;
	assert(t.type == TokenType.INTEGER_LITERAL);
	assert(t.lexeme == "80");

	t = lexer.next()!!;
	assert(t.type == TokenType.RIGHT_PAREN);

	t = lexer.next()!!;
	assert(t.type == TokenType.END_OF_FILE);
}

fn void test_lexer_unterminated_string() @test {
	Lexer lexer;
	lexer.init("\"hello");
	Token? tok = lexer.next();
	if (try tok) unreachable("expected lex to fail");
	assert(@catch(tok) == lexer::UNTERMINATED_STRING);
}

fn void test_lexer_hash_comments() @test {
	Lexer lexer;
	lexer.init("# file comment\nEther # header comment\n/ # separator comment\nIP# comment at EOF");

	Token t = lexer.next()!!;
	assert(t.type == TokenType.IDENTIFIER);
	assert(t.lexeme == "Ether");

	t = lexer.next()!!;
	assert(t.type == TokenType.SLASH);

	t = lexer.next()!!;
	assert(t.type == TokenType.IDENTIFIER);
	assert(t.lexeme == "IP");

	t = lexer.next()!!;
	assert(t.type == TokenType.END_OF_FILE);
}

fn void test_lexer_hash_in_string_is_not_a_comment() @test {
	Lexer lexer;
	lexer.init("Raw(data=\"value #1\") # trailing comment");

	Token t;
	do {
		t = lexer.next()!!;
	} while (t.type != TokenType.STRING_LITERAL);

	assert(t.lexeme == "\"value #1\"");
	while (t.type != TokenType.END_OF_FILE) {
		t = lexer.next()!!;
	}
}

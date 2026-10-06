module flowforge::parser;
import flowforge::ast;
import flowforge::lexer;
import flowforge::token;
import std::collections::list;
import std::core::dstring;

faultdef PARSE_ERROR;

// Detail for the most recent PARSE_ERROR: the fault carries the failure class,
// the side channel carries the human-readable message and source position.
struct ParseError {
	String message;
	usz position;
}

struct Parser {
	Lexer lexer;
	ParseError last_error;
}

fn void? Parser.init(&self, String input) {
	self.lexer.init(input);
	self.last_error = {};
	self.lexer.next()!;
}

fn void? Parser.fail(&self, String message, usz position) @private {
	self.last_error = { .message = message, .position = position };
	return PARSE_ERROR~;
}

fn void? Parser.consume(&self, TokenType expected) {
	if (self.lexer.peek().type == expected) {
		self.lexer.next()!;
		return;
	}
	Token got = self.lexer.peek();
	return self.fail(string::tformat("expected %s but got %s '%s'",
		token::token_type_name(expected),
		token::token_type_name(got.type),
		got.lexeme), got.position);
}

fn String? Parser.parse_string_value(&self, String raw) {
	if (raw.len < 2 || raw[0] != '"' || raw[^1] != '"') {
		if (catch err = self.fail(string::tformat("invalid string literal %s", raw), self.lexer.peek().position)) return err~;
	}
	if (raw.len == 2) return "".copy(tmem);
	String content = raw[1..^2];
	DString out = dstring::temp_with_capacity(content.len);

	for (usz i = 0; i < content.len; i++) {
		if (content[i] == '\\') {
			if (i + 1 >= content.len) {
				if (catch err = self.fail(string::tformat("invalid string escape sequence in %s", raw), self.lexer.peek().position)) return err~;
			}
			switch (content[i + 1]) {
				case 'n': out.append('\n');
				case 't': out.append('\t');
				case 'r': out.append('\r');
				case '\\': out.append('\\');
				case '"': out.append('"');
				case '0': out.append('\0');
				case 'x':
				case 'X':
					if (i + 3 >= content.len) {
						if (catch err = self.fail(string::tformat("invalid string escape sequence in %s", raw), self.lexer.peek().position)) return err~;
					}
					char high = content[i + 2];
					char low = content[i + 3];
					if (!high.is_xdigit() || !low.is_xdigit()) {
						if (catch err = self.fail(string::tformat("invalid string escape sequence in %s", raw), self.lexer.peek().position)) return err~;
					}
					out.append((char)((high.from_hex() << 4) | low.from_hex()));
					i += 3;
				default:
					if (catch err = self.fail(string::tformat("invalid string escape sequence in %s", raw), self.lexer.peek().position)) return err~;
			}
			i++;
		}
		else {
			out.append(content[i]);
		}
	}
	return out.str_view().copy(tmem);
}

fn long? Parser.parse_number_value(&self, String raw) {
	String num = raw;
	bool negative = false;
	if (num.len && num[0] == '-') {
		negative = true;
		num = num[1..];
	}
	int base = 10;
	if (num.starts_with("0x") || num.starts_with("0X")) {
		base = 16;
		num = num[2..];
	}
	else if (num.starts_with("0b") || num.starts_with("0B")) {
		base = 2;
		num = num[2..];
	}
	long? value = num.to_long(base);
	if (catch value) { if (catch err = self.fail(string::tformat("invalid integer literal '%s'", raw), self.lexer.peek().position)) return err~; }
	if (negative) value = -value;
	return value;
}

fn Attribute? Parser.parse_attribute(&self) {
	Token name_tok = self.lexer.peek();
	if (name_tok.type != TokenType.IDENTIFIER) {
		if (catch err = self.fail(string::tformat("expected attribute name but got %s '%s'",
			token::token_type_name(name_tok.type), name_tok.lexeme), name_tok.position)) return err~;
	}
	String name = name_tok.lexeme;
	self.lexer.next()!;

	Attribute attr = { .name = name };

	if (self.lexer.peek().type == TokenType.EQUAL) {
		self.lexer.next()!;
		Expression expression = self.parse_expression()!;
		attr.value.set(expression);
	}
	return attr;
}

fn ScalarValue? Parser.parse_scalar_value(&self) {
	Token val_tok = self.lexer.peek();
	if (val_tok.type == TokenType.STRING_LITERAL) {
		self.lexer.next()!;
		String val = self.parse_string_value(val_tok.lexeme)!;
		return { .kind = ScalarKind.STRING, .string_val = val };
	}
	if (val_tok.type == TokenType.INTEGER_LITERAL) {
		self.lexer.next()!;
		long val = self.parse_number_value(val_tok.lexeme)!;
		return { .kind = ScalarKind.INTEGER, .int_val = val };
	}
	Token got = self.lexer.peek();
	if (catch err = self.fail(string::tformat("expected string or integer value but got %s '%s'",
		token::token_type_name(got.type), got.lexeme), got.position)) return err~;
	unreachable();
}

fn Expression scalar_to_expression(ScalarValue value) {
	switch (value.kind) {
		case ScalarKind.STRING: return ast::expr_string(value.string_val);
		case ScalarKind.INTEGER: return ast::expr_integer(value.int_val);
		case ScalarKind.PACKET: return ast::expr_packet(value.packet_val);
	}
}

fn Header? Parser.parse_header(&self) {
	Token proto_tok = self.lexer.peek();
	if (proto_tok.type != TokenType.IDENTIFIER) {
		if (catch err = self.fail(string::tformat("expected protocol name but got %s '%s'",
			token::token_type_name(proto_tok.type), proto_tok.lexeme), proto_tok.position)) return err~;
	}
	String protocol = proto_tok.lexeme;
	self.lexer.next()!;

	List{Attribute} attrs;
	attrs.tinit();
	if (self.lexer.peek().type != TokenType.LEFT_PAREN) {
		return { .protocol = protocol, .attributes = attrs };
	}
	self.lexer.next()!;

	if (self.lexer.peek().type != TokenType.RIGHT_PAREN) {
		while (true) {
			Attribute attr = self.parse_attribute()!;
			attrs.push(attr);

			if (self.lexer.peek().type == TokenType.COMMA) {
				self.lexer.next()!;
			}
			else { break; }
		}
	}

	self.consume(TokenType.RIGHT_PAREN)!;
	return { .protocol = protocol, .attributes = attrs };
}

fn Packet? Parser.parse_packet_expression(&self) {
	List{Header} headers;
	headers.tinit();

	Header header = self.parse_header()!;
	headers.push(header);

	while (self.lexer.peek().type == TokenType.SLASH) {
		self.lexer.next()!;
		Header next_header = self.parse_header()!;
		headers.push(next_header);
	}
	return headers;
}

fn Expression? Parser.parse_expression(&self) {
	if (self.lexer.peek().type == TokenType.STRING_LITERAL || self.lexer.peek().type == TokenType.INTEGER_LITERAL) {
		ScalarValue value = self.parse_scalar_value()!;
		return scalar_to_expression(value);
	}

	Packet packet = self.parse_packet_expression()!;
	return ast::expr_packet(packet);
}

fn Variable? Parser.parse_variable(&self) {
	Token name_tok = self.lexer.peek();
	if (name_tok.type != TokenType.IDENTIFIER) {
		if (catch err = self.fail(string::tformat("expected variable name but got %s '%s'",
			token::token_type_name(name_tok.type), name_tok.lexeme), name_tok.position)) return err~;
	}
	String name = name_tok.lexeme;
	self.lexer.next()!;

	self.consume(TokenType.COLON)!;

	Expression expression = self.parse_expression()!;
	return { .name = name, .expression = expression };
}

fn Program? Parser.parse_program(&self) {
	List{Variable} variables;
	variables.tinit();

	while (self.lexer.peek().type != TokenType.END_OF_FILE) {
		Variable variable = self.parse_variable()!;
		variables.push(variable);
	}
	return { .variables = variables };
}

fn Packet? Parser.parse_packet(&self) {
	Expression expression = self.parse_expression()!;

	if (self.lexer.peek().type != TokenType.END_OF_FILE) {
		Token extra = self.lexer.peek();
		if (catch err = self.fail(string::tformat("unexpected token '%s' (%s) after packet",
			extra.lexeme, token::token_type_name(extra.type)), extra.position)) return err~;
	}

	ScalarValue value = ast::evaluate(expression);
	if (value.kind != ScalarKind.PACKET) {
		if (catch err = self.fail("expected packet expression", self.lexer.peek().position)) return err~;
	}
	return value.packet_val;
}

fn Program? Parser.parse(&self) => self.parse_program();

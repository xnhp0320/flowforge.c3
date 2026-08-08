module flowforge::parser;
import flowforge::ast;
import flowforge::lexer;
import flowforge::token;
import std::collections::list;
import std::collections::result;
import std::core::dstring;

struct Parser {
	Lexer lexer;
}

fn void Parser.init(&self, String input) {
	self.lexer.init(input);
	(void)self.lexer.next();
}

fn Result{bool, String} Parser.consume(&self, TokenType expected) {
	if (self.lexer.peek().type == expected) {
		Result{Token, String} next = self.lexer.next();
		if (!next.is_ok) return result::err(next.error);
		return result::ok(true);
	}
	return result::err(string::tformat("expected %s but got %s '%s'",
		token::token_type_name(expected),
		token::token_type_name(self.lexer.peek().type),
		self.lexer.peek().lexeme));
}

fn Result{String, String} Parser.parse_string_value(&self, String raw) {
	if (raw.len < 2 || raw[0] != '"' || raw[^1] != '"') {
		return result::err(string::tformat("invalid string literal %s", raw));
	}
	if (raw.len == 2) return result::ok("".copy(tmem));
	String content = raw[1..^2];
	DString out = dstring::temp_with_capacity(content.len);

	for (usz i = 0; i < content.len; i++) {
		if (content[i] == '\\') {
			if (i + 1 >= content.len) {
				return result::err(string::tformat("invalid string escape sequence in %s", raw));
			}
			switch (content[i + 1]) {
				case 'n': out.append('\n'); break;
				case 't': out.append('\t'); break;
				case 'r': out.append('\r'); break;
				case '\\': out.append('\\'); break;
				case '"': out.append('"'); break;
				case '0': out.append('\0'); break;
				case 'x':
				case 'X':
					if (i + 3 >= content.len) {
						return result::err(string::tformat("invalid string escape sequence in %s", raw));
					}
					char high = content[i + 2];
					char low = content[i + 3];
					if (!high.is_xdigit() || !low.is_xdigit()) {
						return result::err(string::tformat("invalid string escape sequence in %s", raw));
					}
					out.append((char)((high.from_hex() << 4) | low.from_hex()));
					i += 3;
					break;
				default:
					return result::err(string::tformat("invalid string escape sequence in %s", raw));
			}
			i++;
		}
		else {
			out.append(content[i]);
		}
	}
	return result::ok(out.str_view().copy(tmem));
}

fn Result{long, String} Parser.parse_number_value(&self, String raw) {
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
	if (catch value) return result::err(string::tformat("invalid integer literal '%s'", raw));
	if (negative) value = -value;
	return result::ok(value);
}

fn Result{Attribute, String} Parser.parse_attribute(&self) {
	Token name_tok = self.lexer.peek();
	if (name_tok.type != TokenType.IDENTIFIER) {
		return result::err(string::tformat("expected attribute name but got %s '%s'",
			token::token_type_name(name_tok.type), name_tok.lexeme));
	}
	String name = name_tok.lexeme;
	Result{Token, String} next = self.lexer.next();
	if (!next.is_ok) return result::err(next.error);

	Attribute attr = { .name = name };

	if (self.lexer.peek().type == TokenType.EQUAL) {
		next = self.lexer.next();
		if (!next.is_ok) return result::err(next.error);
		Result{Expression, String} expression = self.parse_expression();
		if (!expression.is_ok) return result::err(expression.error);
		attr.value.set(expression.value);
	}
	return result::ok(attr);
}

fn Result{ScalarValue, String} Parser.parse_scalar_value(&self) {
	Token val_tok = self.lexer.peek();
	if (val_tok.type == TokenType.STRING_LITERAL) {
		Result{Token, String} next = self.lexer.next();
		if (!next.is_ok) return result::err(next.error);
		Result{String, String} val = self.parse_string_value(val_tok.lexeme);
		if (!val.is_ok) return result::err(val.error);
		return result::ok({ .kind = ScalarKind.STRING, .string_val = val.value });
	}
	if (val_tok.type == TokenType.INTEGER_LITERAL) {
		Result{Token, String} next = self.lexer.next();
		if (!next.is_ok) return result::err(next.error);
		Result{long, String} val = self.parse_number_value(val_tok.lexeme);
		if (!val.is_ok) return result::err(val.error);
		return result::ok({ .kind = ScalarKind.INTEGER, .int_val = val.value });
	}
	return result::err(string::tformat("expected string or integer value but got %s '%s'",
		token::token_type_name(self.lexer.peek().type),
		self.lexer.peek().lexeme));
}

fn Result{Expression, String} scalar_to_expression(ScalarValue value) {
	switch (value.kind) {
		case ScalarKind.STRING: return result::ok(ast::expr_string(value.string_val));
		case ScalarKind.INTEGER: return result::ok(ast::expr_integer(value.int_val));
		default: return result::err("unsupported scalar value");
	}
}

fn Result{Header, String} Parser.parse_header(&self) {
	Token proto_tok = self.lexer.peek();
	if (proto_tok.type != TokenType.IDENTIFIER) {
		return result::err(string::tformat("expected protocol name but got %s '%s'",
			token::token_type_name(proto_tok.type), proto_tok.lexeme));
	}
	String protocol = proto_tok.lexeme;
	Result{Token, String} next = self.lexer.next();
	if (!next.is_ok) return result::err(next.error);

	List{Attribute} attrs;
	attrs.tinit();
	if (self.lexer.peek().type != TokenType.LEFT_PAREN) {
		return result::ok({ .protocol = protocol, .attributes = attrs });
	}
	next = self.lexer.next();
	if (!next.is_ok) return result::err(next.error);

	if (self.lexer.peek().type != TokenType.RIGHT_PAREN) {
		while (true) {
			Result{Attribute, String} attr = self.parse_attribute();
			if (!attr.is_ok) return result::err(attr.error);
			attrs.push(attr.value);

			if (self.lexer.peek().type == TokenType.COMMA) {
				next = self.lexer.next();
				if (!next.is_ok) return result::err(next.error);
			}
			else { break; }
		}
	}

	Result{bool, String} rp = self.consume(TokenType.RIGHT_PAREN);
	if (!rp.is_ok) return result::err(rp.error);
	return result::ok({ .protocol = protocol, .attributes = attrs });
}

fn Result{Packet, String} Parser.parse_packet_expression(&self) {
	List{Header} headers;
	headers.tinit();

	Result{Header, String} header = self.parse_header();
	if (!header.is_ok) return result::err(header.error);
	headers.push(header.value);

	while (self.lexer.peek().type == TokenType.SLASH) {
		Result{Token, String} next = self.lexer.next();
		if (!next.is_ok) return result::err(next.error);
		Result{Header, String} next_header = self.parse_header();
		if (!next_header.is_ok) return result::err(next_header.error);
		headers.push(next_header.value);
	}
	return result::ok(headers);
}

fn Result{Expression, String} Parser.parse_expression(&self) {
	if (self.lexer.peek().type == TokenType.STRING_LITERAL || self.lexer.peek().type == TokenType.INTEGER_LITERAL) {
		Result{ScalarValue, String} value = self.parse_scalar_value();
		if (!value.is_ok) return result::err(value.error);
		return scalar_to_expression(value.value);
	}

	Result{Packet, String} packet = self.parse_packet_expression();
	if (!packet.is_ok) return result::err(packet.error);
	return result::ok(ast::expr_packet(packet.value));
}

fn Result{Variable, String} Parser.parse_variable(&self) {
	Token name_tok = self.lexer.peek();
	if (name_tok.type != TokenType.IDENTIFIER) {
		return result::err(string::tformat("expected variable name but got %s '%s'",
			token::token_type_name(name_tok.type), name_tok.lexeme));
	}
	String name = name_tok.lexeme;
	Result{Token, String} next = self.lexer.next();
	if (!next.is_ok) return result::err(next.error);

	Result{bool, String} colon = self.consume(TokenType.COLON);
	if (!colon.is_ok) return result::err(colon.error);

	Result{Expression, String} expression = self.parse_expression();
	if (!expression.is_ok) return result::err(expression.error);
	return result::ok({ .name = name, .expression = expression.value });
}

fn Result{Program, String} Parser.parse_program(&self) {
	List{Variable} variables;
	variables.tinit();

	while (self.lexer.peek().type != TokenType.END_OF_FILE) {
		Result{Variable, String} variable = self.parse_variable();
		if (!variable.is_ok) return result::err(variable.error);
		variables.push(variable.value);
	}
	return result::ok({ .variables = variables });
}

fn Result{Packet, String} Parser.parse_packet(&self) {
	Result{Expression, String} expression = self.parse_expression();
	if (!expression.is_ok) return result::err(expression.error);

	if (self.lexer.peek().type != TokenType.END_OF_FILE) {
		Token extra = self.lexer.peek();
		return result::err(string::tformat("unexpected token '%s' (%s) after packet",
			extra.lexeme, token::token_type_name(extra.type)));
	}

	ScalarValue? value = ast::evaluate(expression.value);
	if (catch value) return result::err("expected packet expression");
	if (value.kind != ScalarKind.PACKET) return result::err("expected packet expression");
	return result::ok(value.packet_val);
}

fn Result{Program, String} Parser.parse(&self) => self.parse_program();

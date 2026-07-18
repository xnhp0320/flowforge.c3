module flowforge::parser;
import flowforge::ast;
import flowforge::lexer;
import flowforge::token;
import std::collections::list;
import std::core::dstring;

faultdef PARSE_ERROR;

struct Parser {
	Lexer lexer;
	String error;
}

fn void Parser.init(&self, String input) {
	self.lexer.init(input);
	self.error = "";
	if (catch self.lexer.next()) { }
}

fn String Parser.last_error_msg(&self) {
	if (self.error.len) return self.error;
	return self.lexer.last_error_msg();
}

fn bool Parser.consume(&self, TokenType expected) {
	if (self.lexer.peek().type == expected) {
		if (catch self.lexer.next()) return false;
		return true;
	}
	self.error = string::tformat("expected %s but got %s '%s'",
		token::token_type_name(expected),
		token::token_type_name(self.lexer.peek().type),
		self.lexer.peek().lexeme);
	return false;
}

fn String? Parser.parse_string_value(&self, String raw) {
	if (raw.len < 2 || raw[0] != '"' || raw[^1] != '"') return INVALID_STRING~;
	if (raw.len == 2) return "".copy(tmem);
	String content = raw[1..raw.len - 2];
	DString out = dstring::temp_with_capacity(content.len);

	for (usz i = 0; i < content.len; i++) {
		if (content[i] == '\\') {
			if (i + 1 >= content.len) return INVALID_STRING~;
			switch (content[i + 1]) {
				case 'n': out.append('\n'); break;
				case 't': out.append('\t'); break;
				case 'r': out.append('\r'); break;
				case '\\': out.append('\\'); break;
				case '"': out.append('"'); break;
				case '0': out.append('\0'); break;
				case 'x':
				case 'X':
					if (i + 3 >= content.len) return INVALID_STRING~;
					char high = content[i + 2];
					char low = content[i + 3];
					if (!high.is_xdigit() || !low.is_xdigit()) return INVALID_STRING~;
					out.append((char)((high.from_hex() << 4) | low.from_hex()));
					i += 3;
					break;
				default:
					return INVALID_STRING~;
			}
			i++;
		}
		else {
			out.append(content[i]);
		}
	}
	return out.str_view().copy(tmem);
}

faultdef INVALID_STRING;

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
	if (catch value) return INVALID_NUMBER~;
	if (negative) value = -value;
	return value;
}

faultdef INVALID_NUMBER;

fn Attribute? Parser.parse_attribute(&self) {
	Token name_tok = self.lexer.peek();
	if (name_tok.type != TokenType.IDENTIFIER) return PARSE_ERROR~;
	String name = name_tok.lexeme;
	if (catch self.lexer.next()) return PARSE_ERROR~;

	Attribute attr = { .name = name };

	if (self.lexer.peek().type == TokenType.EQUAL) {
		if (catch self.lexer.next()) return PARSE_ERROR~;
		Expression? expression = self.parse_expression();
		if (catch expression) return PARSE_ERROR~;
		attr.value.set(expression);
	}
	return attr;
}

fn ScalarValue? Parser.parse_scalar_value(&self) {
	Token val_tok = self.lexer.peek();
	if (val_tok.type == TokenType.STRING_LITERAL) {
		if (catch self.lexer.next()) return PARSE_ERROR~;
		String? val = self.parse_string_value(val_tok.lexeme);
		if (catch val) {
			self.error = string::tformat("invalid string escape sequence in %s", val_tok.lexeme);
			return PARSE_ERROR~;
		}
		return { .kind = ScalarKind.STRING, .string_val = val };
	}
	if (val_tok.type == TokenType.INTEGER_LITERAL) {
		if (catch self.lexer.next()) return PARSE_ERROR~;
		long? val = self.parse_number_value(val_tok.lexeme);
		if (catch val) {
			self.error = string::tformat("invalid integer literal '%s'", val_tok.lexeme);
			return PARSE_ERROR~;
		}
		return { .kind = ScalarKind.INTEGER, .int_val = val };
	}
	self.error = string::tformat("expected string or integer value but got %s '%s'",
		token::token_type_name(self.lexer.peek().type),
		self.lexer.peek().lexeme);
	return PARSE_ERROR~;
}

fn Expression? scalar_to_expression(ScalarValue value) {
	switch (value.kind) {
		case ScalarKind.STRING: return ast::expr_string(value.string_val);
		case ScalarKind.INTEGER: return ast::expr_integer(value.int_val);
		default: return PARSE_ERROR~;
	}
}

fn Header? Parser.parse_header(&self) {
	Token proto_tok = self.lexer.peek();
	if (proto_tok.type != TokenType.IDENTIFIER) {
		self.error = string::tformat("expected protocol name but got %s '%s'",
			token::token_type_name(proto_tok.type), proto_tok.lexeme);
		return PARSE_ERROR~;
	}
	String protocol = proto_tok.lexeme;
	if (catch self.lexer.next()) return PARSE_ERROR~;

	if (self.lexer.peek().type != TokenType.LEFT_PAREN) {
		return { .protocol = protocol, .attributes = {} };
	}
	if (catch self.lexer.next()) return PARSE_ERROR~;

	List{Attribute} attrs;
	attrs.tinit();

	if (self.lexer.peek().type != TokenType.RIGHT_PAREN) {
		while (true) {
			Attribute? attr = self.parse_attribute();
			if (catch attr) return PARSE_ERROR~;
			attrs.push(attr);

			if (self.lexer.peek().type == TokenType.COMMA) {
				if (catch self.lexer.next()) return PARSE_ERROR~;
			}
			else { break; }
		}
	}

	if (!self.consume(TokenType.RIGHT_PAREN)) return PARSE_ERROR~;
	return { .protocol = protocol, .attributes = attrs.to_tarray() };
}

fn Packet? Parser.parse_packet_expression(&self) {
	List{Header} result;
	result.tinit();

	Header? header = self.parse_header();
	if (catch header) return PARSE_ERROR~;
	result.push(header);

	while (self.lexer.peek().type == TokenType.SLASH) {
		if (catch self.lexer.next()) return PARSE_ERROR~;
		Header? next_header = self.parse_header();
		if (catch next_header) return PARSE_ERROR~;
		result.push(next_header);
	}
	return (Packet)result.to_tarray();
}

fn Expression? Parser.parse_expression(&self) {
	if (self.lexer.peek().type == TokenType.STRING_LITERAL || self.lexer.peek().type == TokenType.INTEGER_LITERAL) {
		ScalarValue? value = self.parse_scalar_value();
		if (catch value) return PARSE_ERROR~;
		return scalar_to_expression(value);
	}

	Packet? packet = self.parse_packet_expression();
	if (catch packet) return PARSE_ERROR~;
	return ast::expr_packet(packet);
}

fn Variable? Parser.parse_variable(&self) {
	Token name_tok = self.lexer.peek();
	if (name_tok.type != TokenType.IDENTIFIER) {
		self.error = string::tformat("expected variable name but got %s '%s'",
			token::token_type_name(name_tok.type), name_tok.lexeme);
		return PARSE_ERROR~;
	}
	String name = name_tok.lexeme;
	if (catch self.lexer.next()) return PARSE_ERROR~;

	if (!self.consume(TokenType.COLON)) return PARSE_ERROR~;

	Expression? expression = self.parse_expression();
	if (catch expression) return PARSE_ERROR~;
	return { .name = name, .expression = expression };
}

fn Program? Parser.parse_program(&self) {
	List{Variable} variables;
	variables.tinit();

	while (self.lexer.peek().type != TokenType.END_OF_FILE) {
		Variable? variable = self.parse_variable();
		if (catch variable) return PARSE_ERROR~;
		variables.push(variable);
	}
	return { .variables = variables.to_tarray() };
}

fn Packet? Parser.parse_packet(&self) {
	Expression? expression = self.parse_expression();
	if (catch expression) return PARSE_ERROR~;

	if (self.lexer.peek().type != TokenType.END_OF_FILE) {
		Token extra = self.lexer.peek();
		self.error = string::tformat("unexpected token '%s' (%s) after packet",
			extra.lexeme, token::token_type_name(extra.type));
		return PARSE_ERROR~;
	}

	ScalarValue? value = ast::evaluate(expression);
	if (catch value) {
		self.error = "expected packet expression";
		return PARSE_ERROR~;
	}
	if (value.kind != ScalarKind.PACKET) {
		self.error = "expected packet expression";
		return PARSE_ERROR~;
	}
	return value.packet_val;
}

fn Program? Parser.parse(&self) => self.parse_program();

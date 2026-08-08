module flowforge::lexer;
import flowforge::token;
import std::collections::result;
import std::core::ascii;

struct Lexer {
	String source;
	usz pos;
	Token current;
}

fn void Lexer.init(&self, String source) {
	self.source = source;
	self.pos = 0;
	self.current = { .type = TokenType.END_OF_FILE, .lexeme = source[source.len..], .position = source.len };
}

fn Token Lexer.peek(&self) => self.current;

fn bool is_identifier_start(char c) => c.is_alpha() || c == '_';
fn bool is_identifier_continue(char c) => c.is_alnum() || c == '_';

// C3 slices are inclusive on both ends; end_exclusive is one past the last character.
fn String lexeme_range(String source, usz start, usz end_exclusive) {
	if (start >= end_exclusive) return "";
	return source[start..end_exclusive - 1];
}

fn void Lexer.skip_whitespace(&self) {
	while (self.pos < self.source.len) {
		char c = self.source[self.pos];
		if (!c.is_space()) break;
		self.pos++;
	}
}

fn Result{Token, String} Lexer.lex_identifier(&self) {
	usz start = self.pos;
	while (self.pos < self.source.len && is_identifier_continue(self.source[self.pos])) {
		self.pos++;
	}
	return result::ok({ .type = TokenType.IDENTIFIER, .lexeme = lexeme_range(self.source, start, self.pos), .position = start });
}

fn Result{Token, String} Lexer.lex_string(&self) {
	usz start = self.pos;
	self.pos++;
	while (self.pos < self.source.len) {
		char c = self.source[self.pos];
		if (c == '"') {
			self.pos++;
			return result::ok({ .type = TokenType.STRING_LITERAL, .lexeme = lexeme_range(self.source, start, self.pos), .position = start });
		}
		if (c == '\\' && self.pos + 1 < self.source.len) {
			self.pos += 2;
		}
		else {
			self.pos++;
		}
	}
	return result::err("unterminated string literal");
}

fn Result{Token, String} Lexer.lex_number(&self) {
	usz start = self.pos;
	if (self.pos < self.source.len && self.source[self.pos] == '0') {
		self.pos++;
		if (self.pos < self.source.len && (self.source[self.pos] == 'x' || self.source[self.pos] == 'X')) {
			self.pos++;
			if (self.pos >= self.source.len || !self.source[self.pos].is_xdigit()) {
				return result::err("invalid hex literal");
			}
			while (self.pos < self.source.len && self.source[self.pos].is_xdigit()) {
				self.pos++;
			}
			return result::ok({ .type = TokenType.INTEGER_LITERAL, .lexeme = lexeme_range(self.source, start, self.pos), .position = start });
		}
		if (self.pos < self.source.len && (self.source[self.pos] == 'b' || self.source[self.pos] == 'B')) {
			self.pos++;
			if (self.pos >= self.source.len || !self.source[self.pos].is_bdigit()) {
				return result::err("invalid binary literal");
			}
			while (self.pos < self.source.len && self.source[self.pos].is_bdigit()) {
				self.pos++;
			}
			return result::ok({ .type = TokenType.INTEGER_LITERAL, .lexeme = lexeme_range(self.source, start, self.pos), .position = start });
		}
	}
	while (self.pos < self.source.len && self.source[self.pos].is_digit()) {
		self.pos++;
	}
	if (self.pos == start) return result::err("invalid number literal");
	return result::ok({ .type = TokenType.INTEGER_LITERAL, .lexeme = lexeme_range(self.source, start, self.pos), .position = start });
}

fn Result{Token, String} Lexer.lex_symbol(&self) {
	usz start = self.pos;
	char c = self.source[self.pos];
	TokenType type;
	switch (c) {
		case '=': type = TokenType.EQUAL; break;
		case '(': type = TokenType.LEFT_PAREN; break;
		case ')': type = TokenType.RIGHT_PAREN; break;
		case ',': type = TokenType.COMMA; break;
		case '/': type = TokenType.SLASH; break;
		case ':': type = TokenType.COLON; break;
		default: return result::err(string::tformat("unexpected character: %c", c));
	}
	self.pos++;
	return result::ok({ type, lexeme_range(self.source, start, self.pos), start });
}

fn Result{Token, String} Lexer.next(&self) {
	self.skip_whitespace();
	if (self.pos >= self.source.len) {
		self.current = { .type = TokenType.END_OF_FILE, .lexeme = self.source[self.source.len..], .position = self.source.len };
		return result::ok(self.current);
	}

	char c = self.source[self.pos];
	Result{Token, String} tok;

	if (c == '-' && self.pos + 1 < self.source.len && self.source[self.pos + 1].is_digit()) {
		usz neg_start = self.pos;
		self.pos++;
		tok = self.lex_number();
		if (!tok.is_ok) return tok;
		tok.value.lexeme = lexeme_range(self.source, neg_start, self.pos);
		tok.value.position = neg_start;
	}
	else if (c == '"') {
		tok = self.lex_string();
	}
	else if (c.is_digit()) {
		tok = self.lex_number();
	}
	else if (is_identifier_start(c)) {
		tok = self.lex_identifier();
	}
	else {
		tok = self.lex_symbol();
	}

	if (!tok.is_ok) return tok;
	self.current = tok.value;
	return tok;
}

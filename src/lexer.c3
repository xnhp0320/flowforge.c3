module flowforge::lexer;
import flowforge::token;
import std::core::ascii;

faultdef LEX_ERROR;

struct Lexer {
	String source;
	usz pos;
	Token current;
	String last_error;
}

fn void Lexer.init(&self, String source) {
	self.source = source;
	self.pos = 0;
	self.last_error = "";
	self.current = { .type = TokenType.END_OF_FILE, .lexeme = source[source.len..], .position = source.len };
}

fn Token Lexer.peek(&self) => self.current;

fn String Lexer.last_error_msg(&self) => self.last_error;

fn bool is_identifier_start(char c) => c.is_alpha() || c == '_';
fn bool is_identifier_continue(char c) => c.is_alnum() || c == '_';
fn bool is_binary_digit(char c) => c == '0' || c == '1';

// C3 slices are inclusive on both ends; end_exclusive is one past the last character.
fn String lexeme_range(String source, usz start, usz end_exclusive) {
	if (start >= end_exclusive) return "";
	return source[start..end_exclusive - 1];
}

fn void Lexer.skip_whitespace(&self) {
	while (self.pos < self.source.len) {
		char c = self.source[self.pos];
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
			self.pos++;
		}
		else { break; }
	}
}

fn Token? Lexer.lex_identifier(&self) {
	usz start = self.pos;
	while (self.pos < self.source.len && is_identifier_continue(self.source[self.pos])) {
		self.pos++;
	}
	return { .type = TokenType.IDENTIFIER, .lexeme = lexeme_range(self.source, start, self.pos), .position = start };
}

fn Token? Lexer.lex_string(&self) {
	usz start = self.pos;
	self.pos++;
	while (self.pos < self.source.len) {
		char c = self.source[self.pos];
		if (c == '"') {
			self.pos++;
			return { .type = TokenType.STRING_LITERAL, .lexeme = lexeme_range(self.source, start, self.pos), .position = start };
		}
		if (c == '\\' && self.pos + 1 < self.source.len) {
			self.pos += 2;
		}
		else {
			self.pos++;
		}
	}
	self.last_error = "unterminated string literal";
	return LEX_ERROR~;
}

fn Token? Lexer.lex_number(&self) {
	usz start = self.pos;
	if (self.pos < self.source.len && self.source[self.pos] == '0') {
		self.pos++;
		if (self.pos < self.source.len && (self.source[self.pos] == 'x' || self.source[self.pos] == 'X')) {
			self.pos++;
			if (self.pos >= self.source.len || !self.source[self.pos].is_xdigit()) {
				self.last_error = "invalid hex literal";
				return LEX_ERROR~;
			}
			while (self.pos < self.source.len && self.source[self.pos].is_xdigit()) {
				self.pos++;
			}
			return { .type = TokenType.INTEGER_LITERAL, .lexeme = lexeme_range(self.source, start, self.pos), .position = start };
		}
		if (self.pos < self.source.len && (self.source[self.pos] == 'b' || self.source[self.pos] == 'B')) {
			self.pos++;
			if (self.pos >= self.source.len || !is_binary_digit(self.source[self.pos])) {
				self.last_error = "invalid binary literal";
				return LEX_ERROR~;
			}
			while (self.pos < self.source.len && is_binary_digit(self.source[self.pos])) {
				self.pos++;
			}
			return { .type = TokenType.INTEGER_LITERAL, .lexeme = lexeme_range(self.source, start, self.pos), .position = start };
		}
	}
	while (self.pos < self.source.len && self.source[self.pos].is_digit()) {
		self.pos++;
	}
	if (self.pos == start) return LEX_ERROR~;
	return { .type = TokenType.INTEGER_LITERAL, .lexeme = lexeme_range(self.source, start, self.pos), .position = start };
}

fn Token? Lexer.lex_symbol(&self) {
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
		default: return LEX_ERROR~;
	}
	self.pos++;
	return { type, lexeme_range(self.source, start, self.pos), start };
}

fn Token? Lexer.next(&self) {
	self.skip_whitespace();
	if (self.pos >= self.source.len) {
		self.current = { .type = TokenType.END_OF_FILE, .lexeme = self.source[self.source.len..], .position = self.source.len };
		return self.current;
	}

	char c = self.source[self.pos];
	Token? result;

	if (c == '-' && self.pos + 1 < self.source.len && self.source[self.pos + 1].is_digit()) {
		usz neg_start = self.pos;
		self.pos++;
		result = self.lex_number();
		if (catch result) return LEX_ERROR~;
		result.lexeme = lexeme_range(self.source, neg_start, self.pos);
		result.position = neg_start;
	}
	else if (c == '"') {
		result = self.lex_string();
	}
	else if (c.is_digit()) {
		result = self.lex_number();
	}
	else if (is_identifier_start(c)) {
		result = self.lex_identifier();
	}
	else {
		result = self.lex_symbol();
		if (catch result) {
			self.last_error = string::tformat("unexpected character: %c", c);
			return LEX_ERROR~;
		}
	}

	if (catch result) return LEX_ERROR~;
	self.current = result;
	return result;
}

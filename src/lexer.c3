module flowforge::lexer;
import flowforge::token;
import std::core::ascii;

faultdef UNTERMINATED_STRING, INVALID_HEX_LITERAL, INVALID_BINARY_LITERAL, INVALID_NUMBER_LITERAL, UNEXPECTED_CHAR;

struct Lexer {
	String source;
	usz pos;
	Token current;
	// Detail for the most recent lex fault (fault names are terse).
	String last_error;
}

fn Token? Lexer.fail(&self, String message, fault err) {
	self.last_error = message;
	return err~;
}

fn void Lexer.init(&self, String source) {
	self.source = source;
	self.pos = 0;
	self.current = { .type = TokenType.END_OF_FILE, .lexeme = source[source.len..], .position = source.len };
	self.last_error = "";
}

fn Token Lexer.peek(&self) => self.current;

fn bool is_identifier_start(char c) => c.is_alpha() || c == '_';
fn bool is_identifier_continue(char c) => c.is_alnum() || c == '_';

// C3 slices are inclusive on both ends; end_exclusive is one past the last character.
fn String lexeme_range(String source, usz start, usz end_exclusive) {
	if (start >= end_exclusive) return "";
	return source[start..end_exclusive - 1];
}

fn void Lexer.skip_trivia(&self) {
	while (self.pos < self.source.len) {
		char c = self.source[self.pos];
		if (c.is_space()) {
			self.pos++;
			continue;
		}
		if (c == '#') {
			while (self.pos < self.source.len && self.source[self.pos] != '\n') {
				self.pos++;
			}
			continue;
		}
		break;
	}
}

fn Token Lexer.lex_identifier(&self) {
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
	return self.fail("unterminated string literal", UNTERMINATED_STRING);
}

fn Token? Lexer.lex_number(&self) {
	usz start = self.pos;
	if (self.pos < self.source.len && self.source[self.pos] == '0') {
		self.pos++;
		if (self.pos < self.source.len && (self.source[self.pos] == 'x' || self.source[self.pos] == 'X')) {
			self.pos++;
			if (self.pos >= self.source.len || !self.source[self.pos].is_xdigit()) {
				return INVALID_HEX_LITERAL~;
			}
			while (self.pos < self.source.len && self.source[self.pos].is_xdigit()) {
				self.pos++;
			}
			return { .type = TokenType.INTEGER_LITERAL, .lexeme = lexeme_range(self.source, start, self.pos), .position = start };
		}
		if (self.pos < self.source.len && (self.source[self.pos] == 'b' || self.source[self.pos] == 'B')) {
			self.pos++;
			if (self.pos >= self.source.len || !self.source[self.pos].is_bdigit()) {
				return INVALID_BINARY_LITERAL~;
			}
			while (self.pos < self.source.len && self.source[self.pos].is_bdigit()) {
				self.pos++;
			}
			return { .type = TokenType.INTEGER_LITERAL, .lexeme = lexeme_range(self.source, start, self.pos), .position = start };
		}
	}
	while (self.pos < self.source.len && self.source[self.pos].is_digit()) {
		self.pos++;
	}
	if (self.pos == start) return INVALID_NUMBER_LITERAL~;
	return { .type = TokenType.INTEGER_LITERAL, .lexeme = lexeme_range(self.source, start, self.pos), .position = start };
}

fn Token? Lexer.lex_symbol(&self) {
	usz start = self.pos;
	char c = self.source[self.pos];
	TokenType type;
	switch (c) {
		case '=': type = TokenType.EQUAL;
		case '(': type = TokenType.LEFT_PAREN;
		case ')': type = TokenType.RIGHT_PAREN;
		case ',': type = TokenType.COMMA;
		case '/': type = TokenType.SLASH;
		case ':': type = TokenType.COLON;
		default: return self.fail(string::tformat("unexpected character: %c", c), UNEXPECTED_CHAR);
	}
	self.pos++;
	return { type, lexeme_range(self.source, start, self.pos), start };
}

fn Token? Lexer.next(&self) {
	self.skip_trivia();
	if (self.pos >= self.source.len) {
		self.current = { .type = TokenType.END_OF_FILE, .lexeme = self.source[self.source.len..], .position = self.source.len };
		return self.current;
	}

	char c = self.source[self.pos];
	Token tok;

	if (c == '-' && self.pos + 1 < self.source.len && self.source[self.pos + 1].is_digit()) {
		usz neg_start = self.pos;
		self.pos++;
		tok = self.lex_number()!;
		tok.lexeme = lexeme_range(self.source, neg_start, self.pos);
		tok.position = neg_start;
	}
	else if (c == '"') {
		tok = self.lex_string()!;
	}
	else if (c.is_digit()) {
		tok = self.lex_number()!;
	}
	else if (is_identifier_start(c)) {
		tok = self.lex_identifier();
	}
	else {
		tok = self.lex_symbol()!;
	}

	self.current = tok;
	return tok;
}

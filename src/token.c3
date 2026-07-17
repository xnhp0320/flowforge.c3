module flowforge::token;

enum TokenType {
	IDENTIFIER,
	STRING_LITERAL,
	INTEGER_LITERAL,
	EQUAL,
	LEFT_PAREN,
	RIGHT_PAREN,
	COMMA,
	SLASH,
	COLON,
	END_OF_FILE,
}

struct Token {
	TokenType type;
	String lexeme;
	usz position;
}

fn String token_type_name(TokenType t) {
	switch (t) {
		case TokenType.IDENTIFIER: return "identifier";
		case TokenType.STRING_LITERAL: return "string literal";
		case TokenType.INTEGER_LITERAL: return "integer literal";
		case TokenType.EQUAL: return "'='";
		case TokenType.LEFT_PAREN: return "'('";
		case TokenType.RIGHT_PAREN: return "')'";
		case TokenType.COMMA: return "','";
		case TokenType.SLASH: return "'/'";
		case TokenType.COLON: return "':'";
		case TokenType.END_OF_FILE: return "end of file";
	}
	return "unknown token";
}

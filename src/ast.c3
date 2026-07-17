module flowforge::ast;

struct Attribute {
	String name;
	bool has_value;
	Expression value;
}

struct Header {
	String protocol;
	Attribute[] attributes;
}

typedef Packet = Header[];

enum ExpressionKind {
	STRING,
	INTEGER,
	PACKET,
}

struct Expression {
	ExpressionKind kind;
	union {
		String string_val;
		long int_val;
		Packet packet_val;
	}
}

struct Variable {
	String name;
	Expression expression;
}

struct Program {
	Variable[] variables;
}

fn Expression expr_string(String s) {
	return { .kind = ExpressionKind.STRING, .string_val = s };
}

fn Expression expr_integer(long v) {
	return { .kind = ExpressionKind.INTEGER, .int_val = v };
}

fn Expression expr_packet(Packet p) {
	return { .kind = ExpressionKind.PACKET, .packet_val = p };
}

enum ScalarKind {
	STRING,
	INTEGER,
	PACKET,
}

struct ScalarValue {
	ScalarKind kind;
	union {
		String string_val;
		long int_val;
		Packet packet_val;
	}
}

fn ScalarValue? evaluate(Expression expr) {
	switch (expr.kind) {
		case ExpressionKind.STRING:
			return { .kind = ScalarKind.STRING, .string_val = expr.string_val };
		case ExpressionKind.INTEGER:
			return { .kind = ScalarKind.INTEGER, .int_val = expr.int_val };
		case ExpressionKind.PACKET:
			return { .kind = ScalarKind.PACKET, .packet_val = expr.packet_val };
	}
	return NO_VALUE~;
}

fn ScalarValue? attr_scalar(Attribute* attr) {
	if (!attr.has_value) return NO_VALUE~;
	return evaluate(attr.value);
}

faultdef NO_VALUE;

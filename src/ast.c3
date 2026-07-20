module flowforge::ast;
import std::collections::list;
import std::collections::maybe;

alias MaybeExpression = Maybe{Expression};

struct Attribute {
	String name;
	MaybeExpression value;
}

struct Header {
	String protocol;
	List{Attribute} attributes;
}

alias Packet = List{Header};

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
	List{Variable} variables;
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
}

fn ScalarValue? attr_scalar(Attribute* attr) {
	Expression? expr = attr.value.get();
	if (catch expr) return NO_VALUE~;
	return evaluate(expr);
}

faultdef NO_VALUE;

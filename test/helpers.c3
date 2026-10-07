module flowforge::testutil;
import flowforge::parser;
import flowforge::ast;
import flowforge::checker;
import flowforge::constructor;
import flowforge::registry;

fn Packet must_parse(String input) {
	Parser p;
	p.init(input)!!;
	return p.parse_packet()!!;
}

fn Program must_parse_program(String input) {
	Parser p;
	p.init(input)!!;
	return p.parse()!!;
}

<* Builds a packet against the default registry. The registry is
   temp-allocated, so the result is only valid within the current temp scope. *>
fn BuildResult build_default(String input) {
	Registry reg = registry::create_default_registry();
	return constructor::build(&reg, must_parse(input));
}

<* Builds a packet against a caller-provided registry. *>
fn BuildResult build_with(String input, Registry* reg) {
	return constructor::build(reg, must_parse(input));
}

fn char byte_at(char[] bytes, usz offset) => bytes[offset];

<* Checks a packet string against the default registry (one-liner for the
   common 'must_parse + checker_with_default + check' test setup). *>
fn CheckResult check_default(String input) {
	Checker checker = checker::checker_with_default();
	return checker.check(must_parse(input));
}

<* Like check_default, but first registers one custom header (legacy
   attr-names/types registration) on top of the default registry. *>
fn CheckResult check_with_header(String input, String protocol, String[] field_names, String[] field_types, String[] packet_options = {}) {
	Registry reg = registry::create_default_registry();
	reg.add_header(protocol, field_names, field_types, packet_options);
	Checker checker = { .registry = &reg };
	return checker.check(must_parse(input));
}

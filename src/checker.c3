module flowforge::checker;
import flowforge::ast;
import flowforge::registry;
import flowforge::validate;
import std::collections::list;
import std::collections::result;
import std::io;
import std::os;

struct CheckResult {
	List{String} warnings;
	List{String} errors;
}

fn bool CheckResult.ok(&self) => self.errors.len() == 0;

fn void CheckResult.tinit(&self) {
	self.warnings.tinit();
	self.errors.tinit();
}

struct Checker {
	Registry* registry;
}

<* @param [&in] self : `checking never mutates the checker or its registry` *>
fn CheckResult Checker.check(&self, Packet packet) {
	CheckResult result;
	result.tinit();

	foreach (header : packet) {
		if (!self.registry.has_header(header.protocol)) {
			result.errors.push(string::tformat("unknown header: '%s'", header.protocol));
			continue;
		}

		foreach (attr : header.attributes) {
			if (!self.registry.has_attr(header.protocol, attr.name)) {
				result.warnings.push(string::tformat("unknown attribute '%s' in header '%s'", attr.name, header.protocol));
				continue;
			}

			Expression? expr = attr.value.get();
			if (catch expr) continue;

			String? type_name = self.registry.attr_type(header.protocol, attr.name);
			ScalarValue value = ast::evaluate(expr);

			if (catch type_name) {
				if (value.kind == ScalarKind.PACKET) {
					CheckResult nested = self.check(value.packet_val);
					foreach (w : nested.warnings) result.warnings.push(w);
					foreach (e : nested.errors) result.errors.push(e);
				}
				continue;
			}

			if (value.kind == ScalarKind.PACKET) {
				result.errors.push(string::tformat("attribute '%s' in header '%s' requires a scalar value", attr.name, header.protocol));
				continue;
			}

			String? failing = self.registry.failing_type_message(type_name);
			if (catch failing) {
				Result{bool, String} valid = validate::validate_scalar_type(type_name, value);
				if (!valid.is_ok) {
					result.errors.push(string::tformat("invalid '%s' in header '%s': %s", attr.name, header.protocol, valid.error));
				}
			}
			else {
				result.errors.push(string::tformat("invalid '%s' in header '%s': %s", attr.name, header.protocol, failing));
			}
		}
	}

	return result;
}

fn void Checker.validate_or_exit(&self, Packet packet) {
	CheckResult result = self.check(packet);
	foreach (w : result.warnings) io::eprintfn("WARNING: %s", w);
	foreach (e : result.errors) io::eprintfn("ERROR: %s", e);
	if (!result.ok()) {
		os::exit(1);
	}
	if (result.warnings.len()) {
		io::eprintfn("%d warning(s) found.", result.warnings.len());
	}
}

fn Checker checker_with_default() => { .registry = mem::tnew(Registry, registry::create_default_registry()) };

fn Checker checker_with_registry(Registry* registry) => { .registry = registry };

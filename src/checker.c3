module flowforge::checker;
import flowforge::ast;
import flowforge::registry;
import flowforge::validate;
import std::collections::list;

struct CheckResult {
	bool ok;
	String[] warnings;
	String[] errors;
}

struct Checker {
	Registry registry;
}

fn CheckResult Checker.check(&self, Packet packet) {
	List{String} warnings;
	warnings.tinit();
	List{String} errors;
	errors.tinit();
	bool ok = true;

	foreach (header : packet) {
		if (!self.registry.has_header(header.protocol)) {
			errors.push(string::tformat("unknown header: '%s'", header.protocol));
			ok = false;
			continue;
		}

		foreach (attr : header.attributes) {
			if (!self.registry.has_attr(header.protocol, attr.name)) {
				warnings.push(string::tformat("unknown attribute '%s' in header '%s'", attr.name, header.protocol));
				continue;
			}

			if (!attr.has_value) continue;

			String? type_name = self.registry.attr_type(header.protocol, attr.name);
			ScalarValue? value = ast::evaluate(attr.value);
			if (catch value) continue;

			if (catch type_name) {
				if (value.kind == ScalarKind.PACKET) {
					CheckResult nested = self.check(value.packet_val);
					ok = ok && nested.ok;
					foreach (w : nested.warnings) warnings.push(w);
					foreach (e : nested.errors) errors.push(e);
				}
				continue;
			}

			if (value.kind == ScalarKind.PACKET) {
				errors.push(string::tformat("attribute '%s' in header '%s' requires a scalar value", attr.name, header.protocol));
				ok = false;
				continue;
			}

			String err_msg = "";
			if (!validate::validate_scalar_type(type_name, value, &err_msg)) {
				errors.push(string::tformat("invalid '%s' in header '%s': %s", attr.name, header.protocol, err_msg));
				ok = false;
			}
		}
	}

	return { .ok = ok, .warnings = warnings.to_tarray(), .errors = errors.to_tarray() };
}

fn Checker checker_with_default() => { .registry = registry::create_default_registry() };

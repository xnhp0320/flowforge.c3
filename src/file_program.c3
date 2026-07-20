module flowforge::file_program;
import flowforge::ast;
import flowforge::generator;
import std::collections::list;
import std::collections::map;

<* Result of extracting file-mode fields from a parsed Program.
   Mirrors packet_editor's parse_file_program: duplicates are errors,
   PACKET is mandatory, PACKET_COUNT must be a positive integer when
   present, and PACKET_COUNT may not be combined with CLI -c. *>
struct FileProgram {
	bool ok;
	List{String} warnings;
	List{String} errors;
	bool has_packet;
	Packet packet;
	generator::MaybeCount packet_count;
}

fn void FileProgram.tinit(&self) {
	self.warnings.tinit();
	self.errors.tinit();
}

<* Builds a FileProgram from a parsed program.
   `cli_packet_count` is the optional -c/--count override; when both it
   and a PACKET_COUNT variable are present, an error is reported. *>
fn FileProgram parse(Program program, generator::MaybeCount cli_packet_count = {}) {
	FileProgram result;
	result.tinit();

	HashMap{String, Variable*} variables;
	variables.tinit();

	foreach (&variable : program.variables) {
		if (variables.has_key(variable.name)) {
			result.errors.push(string::tformat("duplicate variable '%s'", variable.name));
			continue;
		}
		variables.set(variable.name, variable);
	}

	Variable*? packet_var = variables.get("PACKET");
	if (catch packet_var) {
		result.errors.push("missing mandatory variable 'PACKET'");
	}

	Variable*? count_var = variables.get("PACKET_COUNT");
	bool has_count_var = true;
	if (catch count_var) has_count_var = false;

	if (has_count_var && cli_packet_count.has_value) {
		result.errors.push("PACKET_COUNT and -c cannot both be specified");
	}

	if (result.errors.len()) return result;

	// packet_var is present: missing PACKET already returned above.
	ScalarValue? packet_value = ast::evaluate(packet_var.expression);
	if (catch packet_value) {
		result.errors.push("variable 'PACKET' must be a packet expression");
	} else if (packet_value.kind != ScalarKind.PACKET) {
		result.errors.push("variable 'PACKET' must be a packet expression");
	} else {
		result.has_packet = true;
		result.packet = packet_value.packet_val;
	}

	if (has_count_var) {
		ScalarValue? count_value = ast::evaluate(count_var.expression);
		if (catch count_value) {
			result.errors.push("variable 'PACKET_COUNT' must be an integer expression");
		} else if (count_value.kind != ScalarKind.INTEGER) {
			result.errors.push("variable 'PACKET_COUNT' must be an integer expression");
		} else if (count_value.int_val <= 0) {
			result.errors.push("variable 'PACKET_COUNT' must be positive");
		} else {
			result.packet_count.set((ulong)count_value.int_val);
		}
	} else {
		result.packet_count = cli_packet_count;
	}

	foreach (variable : program.variables) {
		if (variable.name != "PACKET" && variable.name != "PACKET_COUNT" &&
			variable.name != "DPDK_ARGS") {
			result.warnings.push(string::tformat("unknown file-mode variable '%s'", variable.name));
		}
	}

	result.ok = result.errors.len() == 0;
	return result;
}

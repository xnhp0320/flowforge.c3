module flowforge::runtime;
import flowforge::ast;
import flowforge::checker;
import flowforge::generator;
import flowforge::registry;
import flowforge::serializer;
import std::collections::list;
import std::collections::map;
import std::collections::maybe;

alias MaybeULong = Maybe{ulong};

faultdef BUILD_ERR;

const ushort RUNTIME_MAX_TX_BATCH_SIZE = 256;
const ulong ULONG_MAX = 0xFFFFFFFFFFFFFFFF;
const ushort USHORT_MAX = 0xFFFF;

struct WorkerResult {
	ulong worker_id;
	ulong lcore_id;
	ushort queue_id;
	ulong first_flow;
	ulong flow_count;
	ulong tx_attempted;
	ulong tx_sent;
	ulong rx_received;
	ulong rx_bytes;
}

struct RunOptions {
	ulong clone_count;
	bool split;
	bool once;
	MaybeULong stats_interval_seconds;
	bool capture;
	Maybe{String} capture_file;
}

struct Result {
	bool ok;
	String[] warnings;
	String[] errors;
	int eal_parsed_args;
	ushort port_id;
	usz packet_len;
	ulong total_flows;
	ulong planned_packets;
	ulong planned_transmissions;
	ulong tx_attempted;
	ulong tx_sent;
	ulong rx_received;
	ulong rx_bytes;
	ulong rx_missed;
	ulong rx_errors;
	ulong pmd_threads;
	ulong rx_threads;
	ulong tx_batch_size;
	ulong clone_count;
	MaybeULong stats_interval_seconds;
	bool split;
	bool once;
	WorkerResult[] workers;
	WorkerResult[] rx_workers;
}

struct Config {
	bool has_packet;
	Packet packet;
	String[] dpdk_args;
	MaybeULong packet_count;
	MaybeULong pmd_threads;
	MaybeULong rx_threads;
	ulong tx_batch_size;
}

struct Runtime {
	Registry* registry;
}

fn FixupOptions live_fixup_options() {
	return {
		.ipv4_checksum = FixupMode.HARDWARE_OFFLOAD,
		.tcp_checksum = FixupMode.HARDWARE_OFFLOAD,
		.udp_checksum = FixupMode.HARDWARE_OFFLOAD,
		.icmp_checksum = FixupMode.SOFTWARE,
	};
}

fn RunOptions default_run_options() => { .clone_count = 1 };

fn Runtime runtime_with_default() {
	return { .registry = mem::tnew(Registry, registry::create_default_registry()) };
}

fn Runtime runtime_with_registry(Registry* registry) => { .registry = registry };

fn String[]? split_dpdk_args(String args, String* error) {
	List{String} result;
	result.tinit();
	DString current;
	current.tinit();
	char quote = 0;
	bool escaping = false;

	foreach (c : args) {
		if (escaping) {
			current.append_char(c);
			escaping = false;
			continue;
		}
		if (c == '\\') {
			escaping = true;
			continue;
		}
		if (quote != 0) {
			if (c == quote) {
				quote = 0;
			} else {
				current.append_char(c);
			}
			continue;
		}
		if (c == '\'' || c == '"') {
			quote = c;
			continue;
		}
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
			if (current.len()) {
				result.push(current.str_view().copy(tmem));
				current.clear();
			}
			continue;
		}
		current.append_char(c);
	}

	if (escaping) {
		*error = "DPDK_ARGS ends with an unfinished escape";
		return BUILD_ERR~;
	}
	if (quote != 0) {
		*error = "DPDK_ARGS contains an unterminated quote";
		return BUILD_ERR~;
	}
	if (current.len()) {
		result.push(current.str_view().copy(tmem));
	}
	return result.to_tarray();
}

fn ulong? positive_integer_var(Variable* variable, String name, List{String}* errors) {
	ScalarValue? value = ast::evaluate(variable.expression);
	if (catch value) {
		errors.push(string::tformat("variable '%s' must be an integer expression", name));
		return BUILD_ERR~;
	}
	if (value.kind != ScalarKind.INTEGER) {
		errors.push(string::tformat("variable '%s' must be an integer expression", name));
		return BUILD_ERR~;
	}
	if (value.int_val <= 0) {
		errors.push(string::tformat("variable '%s' must be positive", name));
		return BUILD_ERR~;
	}
	return (ulong)value.int_val;
}

fn Config? build_config(Program program, Result* result, RunOptions options) {
	List{String} warnings;
	warnings.tinit();
	List{String} errors;
	errors.tinit();

	HashMap{String, Variable*} variables;
	variables.tinit();
	foreach (&variable : program.variables) {
		if (variables.has_key(variable.name)) {
			errors.push(string::tformat("duplicate variable '%s'", variable.name));
			continue;
		}
		variables.set(variable.name, variable);
	}

	Variable*? packet_var = variables.get("PACKET");
	bool has_packet_var = true;
	if (catch packet_var) has_packet_var = false;
	if (!has_packet_var && !options.capture) {
		errors.push("missing mandatory variable 'PACKET'");
	}

	Variable*? dpdk_args_var = variables.get("DPDK_ARGS");
	if (catch dpdk_args_var) {
		errors.push("missing mandatory variable 'DPDK_ARGS'");
	}

	if (errors.len()) {
		result.warnings = warnings.to_tarray();
		result.errors = errors.to_tarray();
		return BUILD_ERR~;
	}

	Config config = { .tx_batch_size = 32 };

	if (has_packet_var) {
		ScalarValue? packet_value = ast::evaluate(packet_var.expression);
		if (catch packet_value) {
			errors.push("variable 'PACKET' must be a packet expression");
		} else if (packet_value.kind != ScalarKind.PACKET) {
			errors.push("variable 'PACKET' must be a packet expression");
		} else {
			config.has_packet = true;
			config.packet = packet_value.packet_val;
		}
	}

	ScalarValue? dpdk_args_value = ast::evaluate(dpdk_args_var.expression);
	if (catch dpdk_args_value) {
		errors.push("variable 'DPDK_ARGS' must be a string expression");
	} else if (dpdk_args_value.kind != ScalarKind.STRING) {
		errors.push("variable 'DPDK_ARGS' must be a string expression");
	} else {
		String split_error = "";
		String[]? args = split_dpdk_args(dpdk_args_value.string_val, &split_error);
		if (catch args) {
			errors.push(split_error);
		} else {
			config.dpdk_args = args;
		}
	}

	Variable*? packet_count_var = variables.get("PACKET_COUNT");
	if (try packet_count_var) {
		ulong? count = positive_integer_var(packet_count_var, "PACKET_COUNT", &errors);
		if (try count) config.packet_count.set(count);
	}

	Variable*? pmd_threads_var = variables.get("PMD_THREADS");
	if (try pmd_threads_var) {
		ulong? threads = positive_integer_var(pmd_threads_var, "PMD_THREADS", &errors);
		if (try threads) {
			if (threads > USHORT_MAX) {
				errors.push("variable 'PMD_THREADS' exceeds the supported Tx queue count");
			} else {
				config.pmd_threads.set(threads);
			}
		}
	}

	Variable*? rx_threads_var = variables.get("RX_THREADS");
	if (try rx_threads_var) {
		ulong? threads = positive_integer_var(rx_threads_var, "RX_THREADS", &errors);
		if (try threads) {
			if (threads > USHORT_MAX) {
				errors.push("variable 'RX_THREADS' exceeds the supported Rx queue count");
			} else {
				config.rx_threads.set(threads);
			}
		}
	}

	Variable*? tx_batch_var = variables.get("TX_BATCH_SIZE");
	if (try tx_batch_var) {
		ulong? batch = positive_integer_var(tx_batch_var, "TX_BATCH_SIZE", &errors);
		if (try batch) {
			if (batch > RUNTIME_MAX_TX_BATCH_SIZE) {
				errors.push(string::tformat("variable 'TX_BATCH_SIZE' must be <= %d", RUNTIME_MAX_TX_BATCH_SIZE));
			} else {
				config.tx_batch_size = batch;
			}
		}
	}

	foreach (variable : program.variables) {
		if (variable.name != "PACKET" && variable.name != "DPDK_ARGS" &&
			variable.name != "PACKET_COUNT" && variable.name != "PMD_THREADS" &&
			variable.name != "RX_THREADS" && variable.name != "TX_BATCH_SIZE") {
			warnings.push(string::tformat("unknown runtime variable '%s'", variable.name));
		}
	}

	result.warnings = warnings.to_tarray();
	result.errors = errors.to_tarray();
	if (errors.len()) return BUILD_ERR~;
	return config;
}

fn ulong checked_transmission_count(ulong flow_count, ulong clone_count, Result* result) {
	if (clone_count == 0) {
		// append via rebuild of errors list is awkward; push into a temp
		List{String} errors;
		errors.tinit();
		foreach (e : result.errors) errors.push(e);
		errors.push("clone count must be positive");
		result.errors = errors.to_tarray();
		return 0;
	}
	if (flow_count > ULONG_MAX / clone_count) {
		List{String} errors;
		errors.tinit();
		foreach (e : result.errors) errors.push(e);
		errors.push("clone expansion has more than 18446744073709551615 packets");
		result.errors = errors.to_tarray();
		return 0;
	}
	return flow_count * clone_count;
}

fn ulong checked_total_transmission_count(ulong planned_flows, ulong worker_count, RunOptions options, Result* result) {
	ulong per_worker = checked_transmission_count(planned_flows, options.clone_count, result);
	if (result.errors.len) return 0;
	if (options.split) return per_worker;
	if (per_worker > ULONG_MAX / worker_count) {
		List{String} errors;
		errors.tinit();
		foreach (e : result.errors) errors.push(e);
		errors.push("worker expansion has more than 18446744073709551615 packets");
		result.errors = errors.to_tarray();
		return 0;
	}
	return per_worker * worker_count;
}

fn void append_strings(List{String}* dest, String[] src) {
	foreach (s : src) dest.push(s);
}

fn Result Runtime.check(&self, Program program, RunOptions options = default_run_options()) {
	Result result;
	result.clone_count = 1;

	Config? config = build_config(program, &result, options);
	if (catch config) return result;

	if (options.capture) {
		result.pmd_threads = config.pmd_threads.has_value ? config.pmd_threads.value : 1;
		result.rx_threads = config.rx_threads.has_value ? config.rx_threads.value : 0;
		result.tx_batch_size = config.tx_batch_size;
		result.ok = true;
		return result;
	}

	PacketGenerator generator = { .registry = self.registry };
	generator::MaybeCount count = config.packet_count;
	PacketGenerationResult generated = generator.prepare(config.packet, count, live_fixup_options());

	List{String} warnings;
	warnings.tinit();
	append_strings(&warnings, result.warnings);
	append_strings(&warnings, generated.warnings);
	List{String} errors;
	errors.tinit();
	append_strings(&errors, result.errors);
	append_strings(&errors, generated.errors);
	result.warnings = warnings.to_tarray();
	result.errors = errors.to_tarray();
	if (!generated.ok || !generated.has_packet) return result;

	result.packet_len = generated.packet.packet_len;
	result.total_flows = generated.packet.flow_plan.total_flows;
	result.planned_packets = generated.packet.flow_plan.planned_packets;
	result.pmd_threads = config.pmd_threads.has_value ? config.pmd_threads.value : 1;
	result.rx_threads = config.rx_threads.has_value ? config.rx_threads.value : 0;
	result.tx_batch_size = config.tx_batch_size;
	result.clone_count = options.clone_count;
	result.stats_interval_seconds = options.stats_interval_seconds;
	result.split = options.split;
	result.once = options.once;
	result.planned_transmissions = checked_total_transmission_count(
		result.planned_packets, result.pmd_threads, options, &result);
	if (result.errors.len) return result;
	result.ok = true;
	return result;
}

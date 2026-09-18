module flowforge::runtime;
import flowforge::ast;
import flowforge::checker;
import flowforge::generator;
import flowforge::registry;
import flowforge::serializer;
import std::collections::list;
import std::collections::map;
import std::collections::maybe;
import std::collections::result;

alias MaybeULong = Maybe{ulong};

faultdef BUILD_ERR;

const ushort RUNTIME_MAX_TX_BATCH_SIZE = 256;
const ulong ULONG_MAX = 0xFFFFFFFFFFFFFFFF;
const ushort USHORT_MAX = 0xFFFF;

struct WorkerResult {
	ushort port_id;
	ulong worker_id;
	ulong lcore_id;
	ushort queue_id;
	ulong first_flow;
	ulong flow_count;
	ulong tx_attempted;
	ulong tx_sent;
	ulong tx_errors;
	ulong rx_received;
	ulong rx_bytes;
}

struct RunOptions {
	ulong clone_count;
	bool split;
	bool once;
	bool jumbo;
	MaybeULong stats_interval_seconds;
	bool capture;
	Maybe{String} capture_file;
	Maybe{String} mempool_seed_dump_file;
}

struct Result {
	bool ok;
	String backend;
	List{String} warnings;
	List{String} errors;
	int eal_parsed_args;
	PortResult[] ports;
	usz packet_len;
	ulong total_flows;
	ulong planned_packets;
	ulong planned_transmissions;
	ulong tx_attempted;
	ulong tx_sent;
	ulong tx_errors;
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

fn void Result.tinit(&self) {
	self.warnings.tinit();
	self.errors.tinit();
}

struct Config {
	String backend;
	String interface_name;
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

fn usz packet_size_limit(RunOptions options) {
	return options.jumbo ? generator::GENERATOR_MAX_PACKET_SIZE : generator::GENERATOR_DEFAULT_MAX_PACKET_SIZE;
}

fn Runtime runtime_with_default() {
	return { .registry = mem::tnew(Registry, registry::create_default_registry()) };
}

fn Runtime runtime_with_registry(Registry* registry) => { .registry = registry };

fn result::Result{String[], String} split_dpdk_args(String args) {
	List{String} parts;
	parts.tinit();
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
				parts.push(current.str_view().copy(tmem));
				current.clear();
			}
			continue;
		}
		current.append_char(c);
	}

	if (escaping) return result::err("DPDK_ARGS ends with an unfinished escape");
	if (quote != 0) return result::err("DPDK_ARGS contains an unterminated quote");
	if (current.len()) {
		parts.push(current.str_view().copy(tmem));
	}
	return result::ok(parts.to_tarray());
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
	bool has_packet_var = true;
	if (catch packet_var) has_packet_var = false;
	if (!has_packet_var && !options.capture) {
		result.errors.push("missing mandatory variable 'PACKET'");
	}

	if (result.errors.len()) return BUILD_ERR~;

	Config config = { .tx_batch_size = 32 };
	Variable*? backend_var = variables.get("BACKEND");
	if (try backend_var) {
		ScalarValue? backend = ast::evaluate(backend_var.expression);
		if (catch backend) {
			result.errors.push("variable 'BACKEND' must be a string expression");
			return BUILD_ERR~;
		}
		if (backend.kind != ScalarKind.STRING) {
			result.errors.push("variable 'BACKEND' must be a string expression");
			return BUILD_ERR~;
		}
		config.backend = backend.string_val;
	} else if (variables.has_key("DPDK_ARGS")) {
		config.backend = "dpdk";
		result.warnings.push("implicit DPDK backend is deprecated; declare BACKEND: \"dpdk\"");
	}
	if (config.backend != "tap" && config.backend != "dpdk") {
		result.errors.push("BACKEND must be 'tap' or 'dpdk'");
		return BUILD_ERR~;
	}
	result.backend = config.backend;
	if (options.jumbo && config.backend != "dpdk") {
		result.errors.push("--jumbo requires the dpdk backend");
		return BUILD_ERR~;
	}
	if (config.backend == "tap") {
		Variable*? iface = variables.get("INTERFACE");
		if (catch iface) {
			result.errors.push("missing mandatory variable 'INTERFACE'");
			return BUILD_ERR~;
		}
		ScalarValue? name = ast::evaluate(iface.expression);
		if (catch name) {
			result.errors.push("variable 'INTERFACE' must be a string expression");
			return BUILD_ERR~;
		}
		if (name.kind != ScalarKind.STRING || !valid_tap_interface(name.string_val)) {
			result.errors.push("INTERFACE must be a nonempty interface name shorter than 16 bytes");
			return BUILD_ERR~;
		}
		config.interface_name = name.string_val;
		if (options.mempool_seed_dump_file.has_value) result.errors.push("--dump-mempool-seed requires the dpdk backend");
	}

	if (has_packet_var) {
		ScalarValue? packet_value = ast::evaluate(packet_var.expression);
		if (catch packet_value) {
			result.errors.push("variable 'PACKET' must be a packet expression");
		} else if (packet_value.kind != ScalarKind.PACKET) {
			result.errors.push("variable 'PACKET' must be a packet expression");
		} else {
			config.has_packet = true;
			config.packet = packet_value.packet_val;
		}
	}

	if (config.backend == "dpdk") {
		Variable*? dpdk_args_var = variables.get("DPDK_ARGS");
		if (catch dpdk_args_var) {
			result.errors.push("missing mandatory variable 'DPDK_ARGS'");
			return BUILD_ERR~;
		}
		ScalarValue? dpdk_args_value = ast::evaluate(dpdk_args_var.expression);
		if (catch dpdk_args_value) {
			result.errors.push("variable 'DPDK_ARGS' must be a string expression");
		} else if (dpdk_args_value.kind != ScalarKind.STRING) {
			result.errors.push("variable 'DPDK_ARGS' must be a string expression");
		} else {
			result::Result{String[], String} args = split_dpdk_args(dpdk_args_value.string_val);
			if (!args.is_ok) {
				result.errors.push(args.error);
			} else {
				config.dpdk_args = args.value;
			}
		}
	}
	Variable*? packet_count_var = variables.get("PACKET_COUNT");
	if (try packet_count_var) {
		ulong? count = positive_integer_var(packet_count_var, "PACKET_COUNT", &result.errors);
		if (try count) config.packet_count.set(count);
	}

	Variable*? pmd_threads_var = variables.get("PMD_THREADS");
	if (try pmd_threads_var) {
		ulong? threads = positive_integer_var(pmd_threads_var, "PMD_THREADS", &result.errors);
		if (try threads) {
			if (threads > USHORT_MAX) {
				result.errors.push("variable 'PMD_THREADS' exceeds the supported Tx queue count");
			} else {
				config.pmd_threads.set(threads);
			}
		}
	}

	Variable*? rx_threads_var = variables.get("RX_THREADS");
	if (try rx_threads_var) {
		ulong? threads = positive_integer_var(rx_threads_var, "RX_THREADS", &result.errors);
		if (try threads) {
			if (threads > USHORT_MAX) {
				result.errors.push("variable 'RX_THREADS' exceeds the supported Rx queue count");
			} else {
				config.rx_threads.set(threads);
			}
		}
	}

	Variable*? tx_batch_var = variables.get("TX_BATCH_SIZE");
	if (try tx_batch_var) {
		ulong? batch = positive_integer_var(tx_batch_var, "TX_BATCH_SIZE", &result.errors);
		if (try batch) {
			if (batch > RUNTIME_MAX_TX_BATCH_SIZE) {
				result.errors.push(string::tformat("variable 'TX_BATCH_SIZE' must be <= %d", RUNTIME_MAX_TX_BATCH_SIZE));
			} else {
				config.tx_batch_size = batch;
			}
		}
	}

	foreach (variable : program.variables) {
		if (variable.name != "BACKEND" && variable.name != "INTERFACE" && variable.name != "PACKET" && variable.name != "DPDK_ARGS" &&
			variable.name != "PACKET_COUNT" && variable.name != "PMD_THREADS" &&
			variable.name != "RX_THREADS" && variable.name != "TX_BATCH_SIZE") {
			result.warnings.push(string::tformat("unknown runtime variable '%s'", variable.name));
		}
	}

	if (result.errors.len()) return BUILD_ERR~;
	return config;
}

fn ulong checked_transmission_count(ulong flow_count, ulong clone_count, Result* result) {
	if (clone_count == 0) {
		result.errors.push("clone count must be positive");
		return 0;
	}
	if (flow_count > ULONG_MAX / clone_count) {
		result.errors.push("clone expansion has more than 18446744073709551615 packets");
		return 0;
	}
	return flow_count * clone_count;
}

fn ulong checked_total_transmission_count(ulong planned_flows, ulong worker_count, RunOptions options, Result* result, ulong port_count = 1) {
	ulong per_worker = checked_transmission_count(planned_flows, options.clone_count, result);
	if (result.errors.len()) return 0;
	ulong multiplier = options.split ? port_count : worker_count;
	if (multiplier == 0) return 0;
	if (per_worker > ULONG_MAX / multiplier) {
		result.errors.push("worker expansion has more than 18446744073709551615 packets");
		return 0;
	}
	return per_worker * multiplier;
}

fn void append_strings(List{String}* dest, List{String} src) {
	foreach (s : src) dest.push(s);
}

fn Result Runtime.check(&self, Program program, RunOptions options = default_run_options()) {
	Result result;
	result.tinit();
	result.clone_count = 1;

	Config? config = build_config(program, &result, options);
	if (catch config) return result;

	if (options.capture) {
		result.pmd_threads = config.backend == "tap" ? 0 : (config.pmd_threads.has_value ? config.pmd_threads.value : 1);
		result.rx_threads = config.rx_threads.has_value ? config.rx_threads.value : (config.backend == "tap" ? 1ul : 0ul);
		result.tx_batch_size = config.tx_batch_size;
		if (config.backend == "tap" && !validate_tap_workers(result.pmd_threads, result.rx_threads, options, &result.errors)) return result;
		result.ok = true;
		return result;
	}

	PacketGenerator generator = { .registry = self.registry, .max_packet_size = packet_size_limit(options) };
	generator::MaybeCount count = config.packet_count;
	PacketGenerationResult generated = generator.prepare(config.packet, count, config.backend == "dpdk" ? live_fixup_options() : (FixupOptions){});

	append_strings(&result.warnings, generated.warnings);
	append_strings(&result.errors, generated.errors);
	if (!generated.ok || !generated.has_packet) return result;

	result.packet_len = generated.packet.base_payload.len;
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
	if (config.backend == "tap") {
		if (config.packet.len() == 0 || config.packet[0].protocol != "Ether") result.errors.push("TAP requires an Ethernet frame starting with Ether()");
		(void)validate_tap_workers(result.pmd_threads, result.rx_threads, options, &result.errors);
	}
	if (result.errors.len()) return result;
	result.ok = true;
	return result;
}

struct PortResult {
	ushort port_id;
	ulong tx_attempted;
	ulong tx_sent;
	ulong tx_errors;
	ulong rx_received;
	ulong rx_bytes;
	ulong rx_missed;
	ulong rx_errors;
	ulong planned_transmissions;
}

// Counts are totals across all ports; a disabled direction has no queues assigned.
fn bool validate_port_workers(usz port_count, ulong tx, ulong rx, List{String}* errors) {
	if (port_count == 0) {
		errors.push("no DPDK ports available");
		return false;
	}
	if ((tx > 0 && tx % port_count != 0) || (rx > 0 && rx % port_count != 0)) {
		errors.push(string::tformat("PMD_THREADS(%d) and RX_THREADS(%d) must each be divisible by %d ports when enabled", tx, rx, port_count));
		return false;
	}
	if (tx + rx > 128) {
		errors.push("total TX and RX workers exceeds runtime limit 128");
		return false;
	}
	return true;
}

struct WorkerAssignment {
	ushort port_id;
	ushort queue_id;
	ulong group_size;
}

fn WorkerAssignment assign_port_worker(ushort[] ports, ulong total, ulong worker) {
	assert(ports.len > 0 && total > 0 && total % (ulong)ports.len == 0 && worker < total);
	ulong group_size = total / (ulong)ports.len;
	return { .port_id = ports[worker / group_size], .queue_id = (ushort)(worker % group_size), .group_size = group_size };
}

fn PortResult summarize_port_workers(ushort port, WorkerResult[] tx, WorkerResult[] rx) {
	PortResult result = { .port_id = port };
	foreach (w : tx) {
		if (w.port_id != port) continue;
		result.tx_sent += w.tx_sent;
		result.tx_attempted += w.tx_attempted;
		result.tx_errors += w.tx_errors;
	}
	foreach (w : rx) {
		if (w.port_id != port) continue;
		result.rx_received += w.rx_received;
		result.rx_bytes += w.rx_bytes;
	}
	return result;
}

module flowforge::runtime;
import flowforge::ast;
import std::collections::list;

fn bool valid_tap_interface(String name) {
	if (name.len == 0 || name.len >= 16 || name == "." || name == "..") return false;
	foreach (c : name) {
		if (c <= 32 || c == 127 || c == '/' || c == ':') return false;
	}
	return true;
}

fn bool validate_tap_workers(ulong tx, ulong rx, RunOptions options, List{String}* errors) {
	if (!validate_port_workers(1, tx, rx, errors)) return false;
	if (options.capture_file.has_value && rx != 1) {
		errors.push("TAP PCAP capture requires exactly one RX worker");
		return false;
	}
	return true;
}

struct FlowRange {
	ulong first;
	ulong count;
}

fn FlowRange assigned_flow_range(ulong flows, ulong workers, ulong worker, bool split) {
	if (!split) return { .first = 0, .count = flows };
	ulong base = flows / workers;
	ulong extra = flows % workers;
	return { .first = worker * base + (worker < extra ? worker : extra), .count = base + (worker < extra ? 1ul : 0ul) };
}

fn Result Runtime.run(&self, Program program, String program_name, RunOptions options = default_run_options()) {
	Result result;
	result.tinit();
	Config? config = build_config(program, &result, options);
	if (catch config) return result;
	if (config.backend == "tap") return self.run_tap(program, options);
	return self.run_dpdk(program, program_name, options);
}

fn Result Runtime.run_dpdk(&self, Program program, String program_name, RunOptions options) @feat(!DPDK) {
	Result result;
	result.tinit();
	result.errors.push("dpdk backend is not compiled in; build the ffg-dpdk target");
	return result;
}

module flowforge_runtime_test;
import flowforge::ast;
import flowforge::parser;
import flowforge::registry;
import flowforge::runtime;
import flowforge::serializer;
import flowforge::testutil;
import flowforge::constructor;

const String TAP_RUNTIME_PROGRAM =
	"DPDK_ARGS: \"--no-huge --no-pci -l 0\"\n"
	"PACKET_COUNT: 3\n"
	"PACKET: Ether(dst=\"ff:ff:ff:ff:ff:ff\",src=\"02:64:74:61:70:00\",type=2048)/IP(src=\"192.168.0.1-192.168.0.3\",dst=\"192.168.0.2\",ttl=64,proto=17)/UDP(sport=1234,dport=5678)";

fn Program must_parse_program(String input) => testutil::must_parse_program(input);

fn void test_valid_mandatory_variables() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge -l 0\"\nPACKET: Ether()/IP(src=\"192.168.0.1\")");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(result.ok);
	assert(result.errors.len() == 0);
	assert(result.total_flows == 1);
	assert(result.planned_packets == 1);
}

fn void test_valid_tap_runtime_program() @test {
	Program program = must_parse_program(TAP_RUNTIME_PROGRAM);
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(result.ok);
	assert(result.errors.len() == 0);
	assert(result.total_flows == 3);
	assert(result.planned_packets == 3);
}

fn void test_tap_runtime_packet_serializes_and_fixes_up() @test {
	Program program = must_parse_program(TAP_RUNTIME_PROGRAM);
	Registry reg = registry::create_default_registry();
	assert(program.variables.len >= 3);
	ScalarValue? value = ast::evaluate(program.variables[2].expression);
	if (catch value) unreachable();
	assert(value.kind == ScalarKind.PACKET);
	BuildResult built = constructor::build(&reg, value.packet_val);
	assert(built.ok);

	char[2048] payload;
	SerializeResult serialized = serializer::serialize_packet(built.packet, &reg, payload[..]);
	assert(serialized.ok);
	assert(serialized.packet_len == 42);

	FixupResult fixed = serializer::fixup_packet(built.packet, &reg, payload[..], serialized.packet_len);
	assert(fixed.ok);
	assert(fixed.errors.len == 0);
}

fn void test_packet_count_caps_cartesian_range_expansion() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0\"\n"
		"PACKET_COUNT: 4\n"
		"PACKET: IP(src=\"[10.0.0.1-10.0.0.3]\",dst=\"[10.0.1.1-10.0.1.2]\")");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(result.ok);
	assert(result.total_flows == 6);
	assert(result.planned_packets == 4);
}

fn void test_port_ranges_contribute_to_flow_expansion() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0\"\n"
		"PACKET: IP()/TCP(sport=\"[10000-10002]\",dport=\"[20000-20001]\")");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(result.ok);
	assert(result.total_flows == 6);
	assert(result.planned_packets == 6);
}

fn void test_pmd_threads_and_batch_size_are_runtime_variables() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0-2\"\n"
		"PMD_THREADS: 2\n"
		"TX_BATCH_SIZE: 16\n"
		"PACKET: IP(src=\"[10.0.0.1-10.0.0.2]\",dst=\"[10.0.1.1-10.0.1.2]\")");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(result.ok);
	assert(result.total_flows == 4);
	assert(result.planned_packets == 4);
	assert(result.pmd_threads == 2);
	assert(result.tx_batch_size == 16);
	assert(result.clone_count == 1);
	assert(!result.split);
	assert(result.planned_transmissions == 8);
	assert(result.workers.len == 0);
}

fn void test_clone_count_multiplies_planned_transmissions() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0\"\n"
		"PACKET_COUNT: 3\n"
		"PACKET: IP(src=\"[10.0.0.1-10.0.0.4]\")");
	Runtime rt = runtime::runtime_with_default();
	RunOptions options = runtime::default_run_options();
	options.clone_count = 5;
	Result result = rt.check(program, options);
	assert(result.ok);
	assert(result.total_flows == 4);
	assert(result.planned_packets == 3);
	assert(result.clone_count == 5);
	assert(result.planned_transmissions == 15);
}

fn void test_pmd_threads_duplicate_planned_transmissions_without_split() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0-2\"\n"
		"PMD_THREADS: 2\n"
		"PACKET: IP(src=\"[10.0.0.1-10.0.0.3]\")");
	Runtime rt = runtime::runtime_with_default();
	RunOptions options = runtime::default_run_options();
	options.clone_count = 2;
	Result result = rt.check(program, options);
	assert(result.ok);
	assert(result.planned_packets == 3);
	assert(result.pmd_threads == 2);
	assert(!result.split);
	assert(result.planned_transmissions == 12);
}

fn void test_split_pmd_threads_partition_planned_transmissions() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0-2\"\n"
		"PMD_THREADS: 2\n"
		"PACKET: IP(src=\"[10.0.0.1-10.0.0.3]\")");
	Runtime rt = runtime::runtime_with_default();
	RunOptions options = runtime::default_run_options();
	options.clone_count = 2;
	options.split = true;
	Result result = rt.check(program, options);
	assert(result.ok);
	assert(result.planned_packets == 3);
	assert(result.pmd_threads == 2);
	assert(result.split);
	assert(result.planned_transmissions == 6);
}

fn void test_once_option_is_reported() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0\"\nPACKET: Ether()");
	Runtime rt = runtime::runtime_with_default();
	RunOptions options = runtime::default_run_options();
	options.once = true;
	Result result = rt.check(program, options);
	assert(result.ok);
	assert(result.once);
	assert(result.planned_transmissions == 1);
}

fn void test_stats_interval_option_is_reported() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0\"\nPACKET: Ether()");
	Runtime rt = runtime::runtime_with_default();
	RunOptions options = runtime::default_run_options();
	options.stats_interval_seconds.set(2);
	Result result = rt.check(program, options);
	assert(result.ok);
	assert(result.stats_interval_seconds.has_value);
	assert(result.stats_interval_seconds.value == 2);
}

fn void test_clone_count_must_be_positive() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0\"\nPACKET: Ether()");
	Runtime rt = runtime::runtime_with_default();
	RunOptions options = runtime::default_run_options();
	options.clone_count = 0;
	Result result = rt.check(program, options);
	assert(!result.ok);
	assert(result.errors.len() == 1);
	assert(result.errors[0] == "clone count must be positive");
}

fn void test_packet_count_larger_than_range_sends_one_pass_only() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0\"\n"
		"PACKET_COUNT: 10\n"
		"PACKET: IP(src=\"10.0.0.1-10.0.0.3\")");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(result.ok);
	assert(result.total_flows == 3);
	assert(result.planned_packets == 3);
}

fn void test_pmd_threads_must_be_positive() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0\"\nPMD_THREADS: 0\nPACKET: Ether()");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(!result.ok);
	assert(result.errors.len() == 1);
	assert(result.errors[0] == "variable 'PMD_THREADS' must be positive");
}

fn void test_tx_batch_size_must_be_positive() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0\"\nTX_BATCH_SIZE: 0\nPACKET: Ether()");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(!result.ok);
	assert(result.errors.len() == 1);
	assert(result.errors[0] == "variable 'TX_BATCH_SIZE' must be positive");
}

fn void test_tx_batch_size_is_capped() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0\"\nTX_BATCH_SIZE: 257\nPACKET: Ether()");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(!result.ok);
	assert(result.errors.len() == 1);
	assert(result.errors[0] == "variable 'TX_BATCH_SIZE' must be <= 256");
}

fn void test_packet_count_must_be_integer() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0\"\nPACKET_COUNT: \"3\"\nPACKET: Ether()");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(!result.ok);
	assert(result.errors.len() == 1);
	assert(result.errors[0] == "variable 'PACKET_COUNT' must be an integer expression");
}

fn void test_packet_count_must_be_positive() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0\"\nPACKET_COUNT: 0\nPACKET: Ether()");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(!result.ok);
	assert(result.errors.len() == 1);
	assert(result.errors[0] == "variable 'PACKET_COUNT' must be positive");
}

fn void test_rejects_range_expansion_overflow() @test {
	Registry reg = registry::create_default_registry();
	reg.register_header("Wide", {
		registry::fld("a", "b64_ranges"),
		registry::fld("b", "b64_ranges"),
	});
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0\"\n"
		"PACKET: Wide(a=\"0-18446744073709551615\",b=\"0-18446744073709551615\")");
	Runtime rt = runtime::runtime_with_registry(&reg);
	Result result = rt.check(program);
	assert(!result.ok);
	assert(result.errors.len() == 1);
	assert(result.errors[0] == "range expansion has more than 18446744073709551615 flows");
}

fn void test_missing_packet() @test {
	Program program = must_parse_program("DPDK_ARGS: \"--no-huge -l 0\"");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(!result.ok);
	assert(result.errors.len() == 1);
	assert(result.errors[0] == "missing mandatory variable 'PACKET'");
}

fn void test_dpdk_args_must_be_string() @test {
	Program program = must_parse_program("DPDK_ARGS: 1\nPACKET: Ether()");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(!result.ok);
	assert(result.errors.len() == 1);
	assert(result.errors[0] == "variable 'DPDK_ARGS' must be a string expression");
}

fn void test_packet_must_be_packet() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge -l 0\"\nPACKET: 1");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(!result.ok);
	assert(result.errors.len() == 1);
	assert(result.errors[0] == "variable 'PACKET' must be a packet expression");
}

fn void test_packet_checker_errors_block_runtime() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge -l 0\"\nPACKET: BadHeader()");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(!result.ok);
	assert(result.errors.len() == 1);
	assert(result.errors[0] == "unknown header: 'BadHeader'");
}

fn void test_rx_threads_is_runtime_variable() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0-3\"\nRX_THREADS: 2\nPACKET: Ether()");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(result.ok);
	assert(result.rx_threads == 2);
}

fn void test_rx_threads_must_be_positive() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0\"\nRX_THREADS: 0\nPACKET: Ether()");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(!result.ok);
	assert(result.errors.len() == 1);
	assert(result.errors[0] == "variable 'RX_THREADS' must be positive");
}

fn void test_rx_threads_default_is_zero() @test {
	Program program = must_parse_program(
		"DPDK_ARGS: \"--no-huge --no-pci -l 0\"\nPACKET: Ether()");
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(program);
	assert(result.ok);
	assert(result.rx_threads == 0);
}

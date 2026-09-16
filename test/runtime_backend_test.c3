module flowforge_runtime_backend_test;
import flowforge::runtime;
import flowforge::testutil;

fn void test_comments_select_only_active_backend() @test {
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(testutil::must_parse_program("# BACKEND: \"dpdk\"\n# DPDK_ARGS: \"-l 0\"\nBACKEND: \"tap\" # chosen\nINTERFACE: \"test0\"\nPACKET: Ether()/IP()/UDP()"));
	assert(result.ok && result.backend == "tap");
	assert(result.warnings.len() == 0);
}

fn void test_backend_validation() @test {
	Runtime rt = runtime::runtime_with_default();
	assert(!rt.check(testutil::must_parse_program("BACKEND: \"tap\"\nPACKET: Ether()")).ok);
	assert(!rt.check(testutil::must_parse_program("BACKEND: \"other\"\nPACKET: Ether()")).ok);
	assert(!rt.check(testutil::must_parse_program("BACKEND: 3\nPACKET: Ether()")).ok);
	assert(!rt.check(testutil::must_parse_program("BACKEND: \"tap\"\nBACKEND: \"dpdk\"\nPACKET: Ether()")).ok);
	assert(!rt.check(testutil::must_parse_program("BACKEND: \"dpdk\"\nPACKET: Ether()")).ok);
}

fn void test_legacy_dpdk_is_checkable_without_eal() @test {
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.check(testutil::must_parse_program("DPDK_ARGS: \"-l 0\"\nPACKET: Ether()"));
	assert(result.ok && result.backend == "dpdk" && result.warnings.len() == 1);
}

fn void test_dpdk_unavailable_has_actionable_error() @test @feat(!DPDK) {
	Runtime rt = runtime::runtime_with_default();
	Result result = rt.run(testutil::must_parse_program("BACKEND: \"dpdk\"\nDPDK_ARGS: \"-l 0\"\nPACKET: Ether()"), "test");
	assert(!result.ok && result.errors[0].contains("ffg-dpdk"));
}

fn void test_tx_cursor_fake_sink_clone_split_and_batch() @test {
	ulong[5] counts;
	for (ulong worker = 0; worker < 2; worker++) {
		TxCursor cursor = { .range = runtime::assigned_flow_range(5, 2, worker, true), .clone_count = 3 };
		while (!cursor.done()) {
			for (usz batch = 0; batch < 4 && !cursor.done(); batch++) {
				counts[cursor.flow()]++;
				cursor.position++;
			}
		}
	}
	foreach (count : counts) assert(count == 3);
	TxCursor empty = { .range = runtime::assigned_flow_range(1, 4, 3, true), .clone_count = 1 };
	assert(empty.done());
}

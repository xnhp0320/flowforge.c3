module flowforge_multiport_test;
import flowforge::runtime;
import std::collections::list;

fn void test_equal_port_worker_groups() @test {
	ushort[2] ports = { 2, 7 };
	List{String} errors;
	errors.tinit();
	assert(runtime::validate_port_workers(2, 8, 4, &errors));
	for (ulong i = 0; i < 8; i++) {
		WorkerAssignment a = runtime::assign_port_worker(ports[..], 8, i);
		assert(a.port_id == ports[i / 4]);
		assert(a.queue_id == i % 4);
		assert(a.group_size == 4);
	}
	for (ulong i = 0; i < 4; i++) {
		WorkerAssignment a = runtime::assign_port_worker(ports[..], 4, i);
		assert(a.port_id == ports[i / 2]);
		assert(a.queue_id == i % 2);
	}
}

fn void test_port_worker_validation() @test {
	List{String} errors;
	errors.tinit();
	assert(runtime::validate_port_workers(1, 1, 0, &errors));
	assert(runtime::validate_port_workers(2, 2, 0, &errors));
	assert(runtime::validate_port_workers(2, 0, 2, &errors));
	assert(!runtime::validate_port_workers(2, 1, 0, &errors));
	assert(!runtime::validate_port_workers(2, 4, 3, &errors));
	assert(!runtime::validate_port_workers(0, 1, 0, &errors));
	assert(!runtime::validate_port_workers(2, 128, 2, &errors));
}

fn void test_each_port_covers_complete_flow_set() @test {
	ushort[2] ports = { 0, 3 };
	foreach (port : ports) {
		ulong next = 0;
		for (ulong i = 0; i < 6; i++) {
			WorkerAssignment a = runtime::assign_port_worker(ports[..], 6, i);
			if (a.port_id != port) continue;
			FlowRange r = runtime::assigned_flow_range(5, a.group_size, a.queue_id, true);
			assert(r.first == next);
			next += r.count;
			FlowRange full = runtime::assigned_flow_range(5, a.group_size, a.queue_id, false);
			assert(full.first == 0 && full.count == 5);
		}
		assert(next == 5);
	}
}

fn void test_multiport_transmission_totals_and_overflow() @test {
	Result result;
	result.tinit();
	RunOptions options = { .clone_count = 3, .split = true };
	assert(runtime::checked_total_transmission_count(5, 4, options, &result, 2) == 30);
	options.split = false;
	assert(runtime::checked_total_transmission_count(5, 4, options, &result, 2) == 60);
	options.split = true;
	options.clone_count = 1;
	assert(runtime::checked_total_transmission_count(0x8000000000000000, 2, options, &result, 2) == 0);
	assert(result.errors.len() == 1);
}

fn void test_statistics_group_by_actual_port_id() @test {
	WorkerResult[3] tx = {
		{ .port_id = 2, .tx_sent = 3, .tx_attempted = 5, .tx_errors = 2 },
		{ .port_id = 7, .tx_sent = 11, .tx_attempted = 12, .tx_errors = 1 },
		{ .port_id = 2, .tx_sent = 4, .tx_attempted = 4 },
	};
	WorkerResult[2] rx = {
		{ .port_id = 7, .rx_received = 2, .rx_bytes = 200 },
		{ .port_id = 2, .rx_received = 3, .rx_bytes = 450 },
	};
	PortResult a = runtime::summarize_port_workers(2, tx[..], rx[..]);
	PortResult b = runtime::summarize_port_workers(7, tx[..], rx[..]);
	assert(a.tx_sent == 7 && a.tx_attempted == 9 && a.tx_errors == 2 && a.rx_received == 3 && a.rx_bytes == 450);
	assert(b.tx_sent == 11 && b.tx_attempted == 12 && b.tx_errors == 1 && b.rx_received == 2 && b.rx_bytes == 200);
	assert(a.tx_sent + b.tx_sent == 18 && a.rx_bytes + b.rx_bytes == 650);
}

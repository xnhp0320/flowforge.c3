module flowforge::runtime;
import flowforge::ast;
import flowforge::generator;
import flowforge::pcap;
import std::io;
import std::io::file;
import std::thread;
import std::collections::list;

extern fn int ff_tap_open(ZString name, int multi, char* error, usz size);
extern fn int ff_tap_send(int fd, char* data, usz size);
extern fn int ff_tap_receive(int fd, char* data, usz size);
extern fn void ff_tap_close(int fd);
extern fn void ff_tap_signals_start();
extern fn void ff_tap_signals_end();
extern fn int ff_tap_stopped();
extern fn long ff_tap_seconds();
extern fn void ff_tap_idle();
extern fn void ff_tap_stop();

// A cursor is transport-independent so scheduling can be tested without TAP.
struct TxCursor {
	FlowRange range;
	ulong clone_count;
	ulong position;
}

fn ulong TxCursor.flow(&self) => self.range.first + self.position / self.clone_count;
fn bool TxCursor.done(&self) => self.position >= self.range.count * self.clone_count;

struct TapTxWorker {
	Mutex mutex;
	GeneratedPacket* packet;
	TxCursor cursor;
	WorkerResult stats;
	int fd;
	ulong batch_size;
	bool once;
	bool done;
	int error;
}

fn int tap_tx_worker(void* arg) {
	int rc;
	@pool_init(mem, 256 * 1024) {
		rc = tap_tx_worker_impl(arg);
	};
	return rc;
}

fn int tap_tx_worker_impl(void* arg) {
	TapTxWorker* worker = arg;
	while (ff_tap_stopped() == 0) {
		worker.mutex.lock()!!;
		if (worker.cursor.done()) {
			if (worker.once || worker.cursor.range.count == 0) {
				worker.done = true;
				worker.mutex.unlock();
				return 0;
			}
			worker.cursor.position = 0;
		}
		@pool() {
			List{String} errors;
			errors.tinit();
			char[generator::GENERATOR_MAX_PACKET_SIZE] buffer;
			for (ulong i = 0; i < worker.batch_size && !worker.cursor.done() && ff_tap_stopped() == 0; i++) {
				char[] payload = buffer[:worker.packet.base_payload.len];
				mem::copy(payload.ptr, worker.packet.base_payload.ptr, (sz)payload.len);
				if (!worker.packet.apply_flow(worker.cursor.flow(), payload, &errors)) { worker.error = -1; break; }
				worker.stats.tx_attempted++;
				int sent = ff_tap_send(worker.fd, payload.ptr, payload.len);
				if (sent == 1) {
					worker.stats.tx_sent++;
				} else if (sent < 0) {
					worker.stats.tx_errors++;
					worker.error = sent;
				}
				worker.cursor.position++;
				if (worker.error != 0) break;
			}
		};
		bool failed = worker.error != 0;
		worker.mutex.unlock();
		if (failed) { ff_tap_stop(); return 1; }
	}
	return 0;
}

struct TapRxWorker {
	Mutex mutex;
	int[] fds;
	usz first;
	usz stride;
	ulong batch_size;
	WorkerResult stats;
	PcapWriter* writer;
	int error;
}

fn int tap_rx_worker(void* arg) {
	TapRxWorker* worker = arg;
	@pool_init(mem, 256 * 1024) {
		char[65536] buffer;
		while (ff_tap_stopped() == 0) {
			bool active = false;
			worker.mutex.lock()!!;
			@pool() {
				for (usz q = worker.first; q < worker.fds.len; q += worker.stride) {
					for (ulong j = 0; j < worker.batch_size; j++) {
						int size = ff_tap_receive(worker.fds[q], &buffer[0], buffer.len);
						if (size <= 0) {
							if (size < 0) worker.error = size;
							break;
						}
						worker.stats.rx_received++;
						worker.stats.rx_bytes += (ulong)size;
						active = true;
						if (worker.writer != null && !worker.writer.write_packet(buffer[:size]).ok) { worker.error = -1; break; }
					}
				}
			};
			bool failed = worker.error != 0;
			worker.mutex.unlock();
			if (failed) { ff_tap_stop(); break; }
			if (!active) ff_tap_idle();
		}
	};
	return 0;
}

fn Result Runtime.run_tap(&self, Program program, RunOptions options) {
	Result result = self.check(program, options);
	if (!result.ok) return result;
	result.ok = false;
	Config? parsed = build_config(program, &result, options);
	if (catch parsed) return result;
	Config config = parsed;
	ulong tx = options.capture ? 0 : result.pmd_threads;
	ulong rx = config.rx_threads.has_value ? config.rx_threads.value : (options.capture ? 1ul : 0ul);
	if (!validate_port_workers(1, tx, rx, &result.errors)) return result;
	if (options.capture_file.has_value && rx != 1) {
		result.errors.push("TAP PCAP capture requires exactly one RX worker");
		return result;
	}
	result.pmd_threads = tx;
	result.rx_threads = rx;
	result.clone_count = options.clone_count;
	result.once = options.once;
	result.split = options.split;
	result.workers = mem::temp_array(WorkerResult, (sz)tx);
	result.rx_workers = mem::temp_array(WorkerResult, (sz)rx);
	result.ports = mem::temp_array(PortResult, 1);
	GeneratedPacket packet;
	if (tx > 0) {
		PacketGenerator gen = { .registry = self.registry };
		PacketGenerationResult generated = gen.prepare(config.packet, config.packet_count);
		append_strings(&result.errors, generated.errors);
		if (!generated.ok) return result;
		packet = generated.packet;
		if (packet.base_payload.len < 14) {
			result.errors.push("TAP requires an Ethernet frame");
			return result;
		}
	}
	int[128] fds;
	usz opened = 0;
	defer { for (usz i = 0; i < opened; i++) ff_tap_close(fds[i]); }
	ulong queues = tx > rx ? tx : rx;
	for (usz i = 0; i < queues; i++) {
		char[256] error;
		int fd = ff_tap_open(config.interface_name.zstr_tcopy(), queues > 1 ? 1 : 0, &error[0], error.len);
		if (fd < 0) {
			result.errors.push(string::tformat("%s", (ZString)&error[0]));
			return result;
		}
		fds[opened++] = fd;
	}
	File output;
	PcapWriter writer;
	bool have_output = false;
	defer { if (have_output) (void)output.close(); }
	if (options.capture_file.has_value) {
		File? file = file::open(options.capture_file.value, "wb");
		if (catch file) {
			result.errors.push("failed to open capture file");
			return result;
		}
		output = file;
		have_output = true;
		writer = { .output = &output };
		if (!writer.write_header().ok) {
			result.errors.push("failed to write pcap header");
			return result;
		}
	}
	TapTxWorker[128] tx_contexts;
	Thread[128] threads;
	TapRxWorker[128] rx_contexts;
	Thread[128] rx_threads;
	for (usz i = 0; i < tx; i++) {
		FlowRange range = assigned_flow_range(result.planned_packets, tx, i, options.split);
		result.workers[i] = { .worker_id = i, .queue_id = (ushort)i, .first_flow = range.first, .flow_count = range.count };
		tx_contexts[i] = { .cursor = { .range = range, .clone_count = options.clone_count }, .stats = result.workers[i], .packet = &packet, .fd = fds[i], .batch_size = config.tx_batch_size, .once = options.once };
	}
	for (usz i = 0; i < rx; i++) {
		result.rx_workers[i] = { .worker_id = i, .queue_id = (ushort)i };
		rx_contexts[i] = { .fds = fds[:opened], .first = i, .stride = (usz)rx, .batch_size = config.tx_batch_size, .stats = result.rx_workers[i], .writer = have_output ? &writer : null };
	}
	ff_tap_signals_start();
	defer ff_tap_signals_end();
	usz launched = 0;
	usz rx_launched = 0;
	for (usz i = 0; i < rx; i++) {
		if (catch rx_contexts[i].mutex.init()) { result.errors.push("failed to initialize TAP RX mutex"); break; }
		if (catch rx_threads[i].create(&tap_rx_worker, &rx_contexts[i])) {
			rx_contexts[i].mutex.destroy();
			result.errors.push("failed to create TAP RX thread");
			break;
		}
		rx_launched++;
	}
	for (usz i = 0; i < tx; i++) {
		if (catch tx_contexts[i].mutex.init()) { result.errors.push("failed to initialize TAP worker mutex"); break; }
		if (catch threads[i].create(&tap_tx_worker, &tx_contexts[i])) {
			tx_contexts[i].mutex.destroy();
			result.errors.push("failed to create TAP TX thread");
			break;
		}
		launched++;
	}
	long next_stats = ff_tap_seconds() + (long)(options.stats_interval_seconds.has_value ? options.stats_interval_seconds.value : 1);
	while (ff_tap_stopped() == 0 && result.errors.len() == 0) {
		bool all_done = true;
		for (usz i = 0; i < launched; i++) {
			tx_contexts[i].mutex.lock()!!;
			result.workers[i] = tx_contexts[i].stats;
			all_done = all_done && tx_contexts[i].done;
			tx_contexts[i].mutex.unlock();
		}
		for (usz i = 0; i < rx_launched; i++) {
			rx_contexts[i].mutex.lock()!!;
			result.rx_workers[i] = rx_contexts[i].stats;
			rx_contexts[i].mutex.unlock();
		}
		if (options.stats_interval_seconds.has_value && ff_tap_seconds() >= next_stats) {
			PortResult stats = summarize_port_workers(0, result.workers, result.rx_workers);
			io::printfn("port 0: TX %d RX %d bytes %d", stats.tx_sent, stats.rx_received, stats.rx_bytes);
			next_stats = ff_tap_seconds() + (long)options.stats_interval_seconds.value;
		}
		if (options.once && tx > 0 && all_done && rx == 0) break;
		ff_tap_idle();
	}
	ff_tap_stop();
	for (usz i = 0; i < launched; i++) {
		(void)threads[i].join()!!;
		result.workers[i] = tx_contexts[i].stats;
		if (tx_contexts[i].error != 0) result.errors.push(string::tformat("TAP TX worker %d failed: %d", i, tx_contexts[i].error));
		tx_contexts[i].mutex.destroy();
	}
	for (usz i = 0; i < rx_launched; i++) {
		(void)rx_threads[i].join()!!;
		result.rx_workers[i] = rx_contexts[i].stats;
		if (rx_contexts[i].error != 0) result.errors.push(string::tformat("TAP RX worker %d failed: %d", i, rx_contexts[i].error));
		rx_contexts[i].mutex.destroy();
	}
	if (have_output) {
		have_output = false;
		if (catch output.close()) result.errors.push("failed to flush or close capture file");
	}
	PortResult stats = summarize_port_workers(0, result.workers, result.rx_workers);
	stats.planned_transmissions = result.planned_transmissions;
	result.ports[0] = stats;
	result.tx_sent = stats.tx_sent;
	result.tx_attempted = stats.tx_attempted;
	result.tx_errors = stats.tx_errors;
	result.rx_received = stats.rx_received;
	result.rx_bytes = stats.rx_bytes;
	result.ok = result.errors.len() == 0 && result.tx_errors == 0;
	return result;
}

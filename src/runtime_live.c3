<* Live DPDK runtime for FlowForge (Slices B/C/D).

   Extends the `flowforge::runtime` module (see runtime.c3 for the DPDK-free
   check path) with the EAL-backed transmit and capture pipeline, mirroring the
   C++ `packet::Runtime::run` semantics. All DPDK access goes through the
   `flowforge::dpdk` bindings / C shim so this file never includes DPDK headers.

   e2e execution needs a real EAL, root privileges and /dev/net/tun access; the
   logic here is exercised through unit tests for the parts that can run without
   the EAL (see runtime_dpdk_test.c3). *>
module flowforge::runtime;
import flowforge::ast;
import flowforge::dpdk;
import flowforge::checker;
import flowforge::generator;
import flowforge::serializer;
import flowforge::pcap;
import flowforge::stats_format;
import std::atomic::types;
import std::collections::list;
import std::io;
import std::io::file;

// --- runtime constants (mirror runtime.cpp) -------------------------------
const ushort RUNTIME_PORT_ID = 0;
const ushort RUNTIME_RX_DESCRIPTORS = 128;
const ushort RUNTIME_TX_DESCRIPTORS = 512;
const uint RUNTIME_MBUF_CACHE_SIZE = 250;
const ushort RUNTIME_RX_BATCH_SIZE = 32;
const ushort RUNTIME_MAX_RX_BATCH_SIZE = 128;
const uint RUNTIME_CAPTURE_MBUF_COUNT = 8191;
const usz RUNTIME_MAX_LCORES = 128;
const usz RUNTIME_CACHE_LINE_SIZE = 64;

// DPDK worker lcores run on threads that c3c never sees, so they have no
// implicitly-created temp allocator. Each worker entry point installs its own
// pool via `@pool_init` before touching any tmem-backed helper (e.g. the
// `string::tformat` used on error paths).
const usz RUNTIME_WORKER_POOL_SIZE = 256 * 1024;

const String RUNTIME_TAP_NAME = "net_tap0";
const String RUNTIME_TAP_ARGS = "iface=packet_tap0,mac=fixed";
const String RUNTIME_TAP_IFACE = "packet_tap0";

// --- libc helpers used for signals / pacing -------------------------------
alias SignalHandler = fn void(int sig);
extern fn void* signal(int signum, SignalHandler handler) @private;
extern fn int usleep(uint usec) @private;
extern fn long time(long* tloc) @private;

const int SIGINT = 2;
const int SIGTERM = 15;

bool runtime_stop_requested @private = false;

fn void request_runtime_stop(int sig) @private {
	runtime_stop_requested = true;
}

fn void install_signal_handlers() @private {
	runtime_stop_requested = false;
	signal(SIGINT, &request_runtime_stop);
	signal(SIGTERM, &request_runtime_stop);
}

fn ZString zstr(String value) @private => value.zstr_tcopy();

// --- worker contexts ------------------------------------------------------
struct PublishedWorkerStats @align(64) {
	Atomic{ulong} tx_attempted;
	Atomic{ulong} tx_sent;
	char[48] _pad;
}

struct PublishedRxWorkerStats @align(64) {
	Atomic{ulong} rx_received;
	Atomic{ulong} rx_bytes;
	char[48] _pad;
}

$assert PublishedWorkerStats::size == RUNTIME_CACHE_LINE_SIZE;
$assert PublishedRxWorkerStats::size == RUNTIME_CACHE_LINE_SIZE;

struct WorkerContext {
	ulong worker_id;
	ulong lcore_id;
	ushort port_id;
	ushort queue_id;
	ulong first_flow;
	ulong flow_count;
	ulong clone_count;
	bool once;
	bool split;
	Mempool* mbuf_pool;
	PacketGenerator* generator;
	GeneratedPacket* packet;
	ushort batch_size;
	ulong tx_attempted;
	ulong tx_sent;
	PublishedWorkerStats* published_stats;
	List{String} errors;
}

struct RxWorkerContext {
	ulong worker_id;
	ulong lcore_id;
	ushort port_id;
	ushort queue_id;
	ushort batch_size;
	ulong rx_received;
	ulong rx_bytes;
	PublishedRxWorkerStats* published_stats;
}

struct WorkerStatsView {
	ulong worker_id;
	ulong lcore_id;
	ushort queue_id;
	ulong first_flow;
	ulong flow_count;
	ulong tx_attempted;
	ulong tx_sent;
}

struct RxWorkerStatsView {
	ulong worker_id;
	ulong lcore_id;
	ushort queue_id;
	ulong rx_received;
	ulong rx_bytes;
}

struct LiveStatsState {
	ulong[RUNTIME_MAX_LCORES] previous_tx_sent;
	ulong[RUNTIME_MAX_LCORES] previous_rx_received;
	ulong previous_imissed;
	ulong previous_ierrors;
	long start;
	long last;
	long next;
}

struct FlowRange {
	ulong first;
	ulong count;
}

struct SeedContext {
	char* base_ptr;
	usz base_len;
	uint seeded;
}

// --- offload --------------------------------------------------------------

<* Applies a hardware-checksum offload request to an mbuf (wraps the shim,
   mirroring apply_dpdk_offload_request in the C++ reference). *>
fn void apply_dpdk_offload(Mbuf* mbuf, PacketOffloadRequest request) {
	dpdk::ff_apply_dpdk_offload(mbuf,
		(int)request.layer3.ordinal,
		request.ipv4_checksum ? 1 : 0,
		request.tcp_checksum ? 1 : 0,
		request.udp_checksum ? 1 : 0,
		(ulong)request.l2_len,
		(ulong)request.l3_len,
		(ulong)request.l4_len);
}

// --- EAL / port helpers ---------------------------------------------------

fn int init_eal(String[] dpdk_args, String eal_program_name, Result* result, List{String}* errors) @private {
	usz argc = dpdk_args.len + 1;
	ZString[] argv = mem::temp_array(ZString, (sz)argc);
	argv[0] = eal_program_name.zstr_tcopy();
	foreach (i, arg : dpdk_args) {
		argv[i + 1] = arg.zstr_tcopy();
	}

	int parsed = dpdk::rte_eal_init((int)argc, (char**)argv.ptr);
	if (parsed < 0) {
		errors.push(string::tformat("rte_eal_init failed: %s", dpdk::strerror(dpdk::ff_rte_errno())));
		return parsed;
	}
	result.eal_parsed_args = parsed;
	return parsed;
}

fn void cleanup_eal(List{String}* warnings) @private {
	int rc = dpdk::rte_eal_cleanup();
	if (rc < 0) {
		warnings.push(string::tformat("rte_eal_cleanup failed: %s", dpdk::strerror(dpdk::ff_rte_errno())));
	}
}

fn uint mbuf_count_for(ulong worker_count, ushort batch_size) @private {
	ulong in_flight = worker_count * ((ulong)RUNTIME_TX_DESCRIPTORS + (ulong)batch_size * 2);
	ulong total = in_flight + RUNTIME_MBUF_CACHE_SIZE;
	if (total < 8191) total = 8191;
	return (uint)total;
}

fn void seed_mbuf_base_payload(Mempool* pool, void* opaque, void* obj, uint index) @private {
	SeedContext* context = opaque;
	Mbuf* mbuf = obj;
	char* data = mbuf.mtod();
	mem::copy(data, context.base_ptr, (sz)context.base_len);
	context.seeded++;
}

fn Mempool* make_mbuf_pool(GeneratedPacket* packet, ulong worker_count, ushort batch_size, List{String}* errors) @private {
	Mempool* pool = dpdk::rte_pktmbuf_pool_create(
		zstr("packet_runtime_mbuf_pool"),
		mbuf_count_for(worker_count, batch_size),
		RUNTIME_MBUF_CACHE_SIZE,
		0,
		(ushort)dpdk::ff_mbuf_default_buf_size(),
		(int)dpdk::rte_socket_id());
	if (pool == null) {
		errors.push(string::tformat("rte_pktmbuf_pool_create failed: %s", dpdk::strerror(dpdk::ff_rte_errno())));
		return null;
	}

	SeedContext context = { .base_ptr = packet.base_payload.ptr, .base_len = packet.base_payload.len };
	uint iterated = dpdk::rte_mempool_obj_iter(pool, &seed_mbuf_base_payload, &context);
	if (iterated == 0 || context.seeded != iterated) {
		errors.push("failed to seed packet base payload into the mbuf pool");
	}
	return pool;
}

fn bool check_tap_permission(List{String}* errors) @private {
	char[256] err_buf;
	err_buf[0] = 0;
	int rc = dpdk::ff_check_tap_permission(RUNTIME_TAP_IFACE.zstr_tcopy(), &err_buf[0], 256);
	if (rc != 0) {
		ZString message = (ZString)&err_buf[0];
		errors.push(message.str_view().copy(tmem));
		return false;
	}
	return true;
}

fn bool probe_tap_port(List{String}* errors) @private {
	int rc = dpdk::rte_eal_hotplug_add(zstr("vdev"), zstr(RUNTIME_TAP_NAME), zstr(RUNTIME_TAP_ARGS));
	if (rc < 0) {
		errors.push(string::tformat("failed to create TAP port '%s': %s", RUNTIME_TAP_NAME, dpdk::strerror(-rc)));
		return false;
	}
	return true;
}

fn bool configure_and_start_port(ushort port_id, ushort rx_queue_count, ushort tx_queue_count, Mempool* mbuf_pool, List{String}* errors, Result* result) @private {
	ushort port_count = dpdk::rte_eth_dev_count_avail();
	if (port_count == 0) {
		errors.push("no DPDK ethdev ports are available");
		return false;
	}
	if (port_id >= port_count) {
		errors.push(string::tformat("requested DPDK port %d but only %d port(s) are available", port_id, port_count));
		return false;
	}

	int rc = dpdk::ff_eth_dev_configure(port_id, rx_queue_count, tx_queue_count);
	if (rc < 0) {
		errors.push(string::tformat("rte_eth_dev_configure failed for port %d: %s", port_id, dpdk::strerror(-rc)));
		return false;
	}

	int socket = dpdk::rte_eth_dev_socket_id(port_id);
	for (ushort queue_id = 0; queue_id < rx_queue_count; queue_id++) {
		rc = dpdk::rte_eth_rx_queue_setup(port_id, queue_id, RUNTIME_RX_DESCRIPTORS, (uint)socket, null, mbuf_pool);
		if (rc < 0) {
			errors.push(string::tformat("rte_eth_rx_queue_setup failed for port %d queue %d: %s", port_id, queue_id, dpdk::strerror(-rc)));
			return false;
		}
	}

	for (ushort queue_id = 0; queue_id < tx_queue_count; queue_id++) {
		rc = dpdk::rte_eth_tx_queue_setup(port_id, queue_id, RUNTIME_TX_DESCRIPTORS, (uint)socket, null);
		if (rc < 0) {
			errors.push(string::tformat("rte_eth_tx_queue_setup failed for port %d queue %d: %s", port_id, queue_id, dpdk::strerror(-rc)));
			return false;
		}
	}

	rc = dpdk::rte_eth_dev_start(port_id);
	if (rc < 0) {
		errors.push(string::tformat("rte_eth_dev_start failed for port %d: %s", port_id, dpdk::strerror(-rc)));
		return false;
	}

	result.port_id = port_id;
	return true;
}

fn void stop_and_close_port(ushort port_id, List{String}* warnings) @private {
	int rc = dpdk::rte_eth_dev_stop(port_id);
	if (rc < 0) {
		warnings.push(string::tformat("rte_eth_dev_stop failed for port %d: %s", port_id, dpdk::strerror(-rc)));
	}
	rc = dpdk::rte_eth_dev_close(port_id);
	if (rc < 0) {
		warnings.push(string::tformat("rte_eth_dev_close failed for port %d: %s", port_id, dpdk::strerror(-rc)));
	}
}

// --- packet preparation / transmit ----------------------------------------

fn void free_unsent(Mbuf** packets, ushort begin, ushort end) @private {
	for (ushort index = begin; index < end; index++) {
		dpdk::ff_pktmbuf_free(packets[index]);
	}
}

fn bool prepare_batch_packet(WorkerContext* context, Mbuf* mbuf, ulong flow_index) @private {
	char* packet_data = mbuf.append((ushort)context.packet.packet_len);
	if (packet_data == null) {
		context.errors.push(string::tformat("packet length %d does not fit in an mbuf", context.packet.packet_len));
		return false;
	}

	mbuf.reset_offload();

	char[] payload = packet_data[:context.packet.packet_len];
	if (!context.generator.apply_flow(context.packet, flow_index, payload, &context.errors)) {
		return false;
	}

	apply_dpdk_offload(mbuf, context.packet.fixup_plan.offload);
	return true;
}

fn void publish_worker_stats(WorkerContext* context) @private {
	if (context.published_stats == null) return;
	context.published_stats.tx_attempted.store(context.tx_attempted);
	context.published_stats.tx_sent.store(context.tx_sent);
}

fn void publish_rx_worker_stats(RxWorkerContext* context) @private {
	if (context.published_stats == null) return;
	context.published_stats.rx_received.store(context.rx_received);
	context.published_stats.rx_bytes.store(context.rx_bytes);
}

fn bool transmit_batch(WorkerContext* context, Mbuf** packets, ushort count) @private {
	context.tx_attempted += count;

	ushort prepared = dpdk::ff_eth_tx_prepare(context.port_id, context.queue_id, packets, count);
	if (prepared != count) {
		free_unsent(packets, prepared, count);
		context.errors.push(string::tformat("rte_eth_tx_prepare prepared %d of %d packet(s)", prepared, count));
		if (prepared == 0) {
			return false;
		}
	}

	ushort sent_total = 0;
	while (sent_total < prepared) {
		ushort sent = dpdk::ff_eth_tx_burst(context.port_id, context.queue_id, &packets[sent_total], (ushort)(prepared - sent_total));
		if (sent == 0) break;
		sent_total += sent;
	}

	context.tx_sent += sent_total;
	if (sent_total != prepared) {
		free_unsent(packets, sent_total, prepared);
		context.errors.push(string::tformat("rte_eth_tx_burst sent %d of %d prepared packet(s)", sent_total, prepared));
		return false;
	}

	return prepared == count;
}

// Worker error strings are built with tmem but are read back by the main thread
// after the worker's pool is destroyed, so copy them onto the (main-owned) heap
// list before the pool unwinds.
fn void heapify_errors(List{String}* errors) @private {
	foreach (i, e : errors) {
		errors.set(i, e.copy(mem));
	}
}

fn int run_worker_once(void* arg) @private {
	WorkerContext* context = arg;
	int rc;
	@pool_init(mem, RUNTIME_WORKER_POOL_SIZE) {
		rc = run_worker_once_impl(context);
		heapify_errors(&context.errors);
	};
	return rc;
}

fn int run_worker_once_impl(WorkerContext* context) @private {
	Mbuf*[RUNTIME_MAX_TX_BATCH_SIZE] batch;
	ulong planned = context.flow_count * context.clone_count;
	if (planned == 0) return 0;

	ulong transmitted = 0;
	while (transmitted < planned && !runtime_stop_requested) {
		ulong remaining = planned - transmitted;
		ushort count = (ushort)(context.batch_size < remaining ? context.batch_size : remaining);
		if (dpdk::ff_pktmbuf_alloc_bulk(context.mbuf_pool, &batch[0], count) != 0) {
			context.errors.push(string::tformat("rte_pktmbuf_alloc_bulk failed for %d packet(s): %s", count, dpdk::strerror(dpdk::ff_rte_errno())));
			return 1;
		}

		for (ushort i = 0; i < count; i++) {
			ulong flow_index = context.first_flow + (transmitted + i) / context.clone_count;
			if (!prepare_batch_packet(context, batch[i], flow_index)) {
				free_unsent(&batch[0], 0, count);
				return 1;
			}
		}

		if (!transmit_batch(context, &batch[0], count)) {
			publish_worker_stats(context);
			return 1;
		}
		publish_worker_stats(context);
		transmitted += count;
	}
	return 0;
}

fn int run_worker(void* arg) @private {
	WorkerContext* context = arg;
	int rc;
	@pool_init(mem, RUNTIME_WORKER_POOL_SIZE) {
		rc = run_worker_impl(context);
		heapify_errors(&context.errors);
	};
	return rc;
}

fn int run_worker_impl(WorkerContext* context) @private {
	Mbuf*[RUNTIME_MAX_TX_BATCH_SIZE] batch;
	if (context.flow_count == 0) return 0;

	ulong global_transmission = 0;
	while (!runtime_stop_requested) {
		ushort count = context.batch_size;
		if (dpdk::ff_pktmbuf_alloc_bulk(context.mbuf_pool, &batch[0], count) != 0) {
			context.errors.push(string::tformat("rte_pktmbuf_alloc_bulk failed for %d packet(s): %s", count, dpdk::strerror(dpdk::ff_rte_errno())));
			return 1;
		}

		for (ushort i = 0; i < count; i++) {
			ulong local_transmission = global_transmission + i;
			ulong flow_index = context.first_flow + (local_transmission / context.clone_count) % context.flow_count;
			if ((short)i < (short)count - 1) {
			    @prefetch(batch[i].mtod(), PrefetchLocality.FAR, true);
			}
			if (!prepare_batch_packet(context, batch[i], flow_index)) {
				free_unsent(&batch[0], 0, count);
				return 1;
			}
		}

		if (!transmit_batch(context, &batch[0], count)) {
			publish_worker_stats(context);
			return 1;
		}
		publish_worker_stats(context);
		global_transmission += count;
	}
	return 0;
}

fn int run_rx_worker(void* arg) @private {
	RxWorkerContext* context = arg;
	int rc;
	@pool_init(mem, RUNTIME_WORKER_POOL_SIZE) {
		rc = run_rx_worker_impl(context);
	};
	return rc;
}

fn int run_rx_worker_impl(RxWorkerContext* context) @private {
	Mbuf*[RUNTIME_MAX_RX_BATCH_SIZE] mbufs;

	while (!runtime_stop_requested) {
		ushort nb_rx = dpdk::ff_eth_rx_burst(context.port_id, context.queue_id, &mbufs[0], context.batch_size);
		if (nb_rx == 0) continue;

		ulong bytes = 0;
		for (ushort i = 0; i < nb_rx; i++) {
			bytes += mbufs[i].pkt_len;
		}

		context.rx_received += nb_rx;
		context.rx_bytes += bytes;
		publish_rx_worker_stats(context);
		dpdk::ff_pktmbuf_free_bulk(&mbufs[0], nb_rx);
	}
	return 0;
}

fn FlowRange assigned_flow_range(ulong planned_flows, ulong worker_count, ulong worker_id, bool split) @private {
	if (!split) {
		return { .first = 0, .count = planned_flows };
	}
	ulong base = planned_flows / worker_count;
	ulong extra = planned_flows % worker_count;
	ulong count = base + (worker_id < extra ? 1ul : 0ul);
	ulong first = worker_id * base + (worker_id < extra ? worker_id : extra);
	return { .first = first, .count = count };
}

fn WorkerResult make_worker_result(WorkerContext* context) @private {
	return {
		.worker_id = context.worker_id,
		.lcore_id = context.lcore_id,
		.queue_id = context.queue_id,
		.first_flow = context.first_flow,
		.flow_count = context.flow_count,
		.tx_attempted = context.tx_attempted,
		.tx_sent = context.tx_sent,
	};
}

fn WorkerResult make_rx_worker_result(RxWorkerContext* context) @private {
	return {
		.worker_id = context.worker_id,
		.lcore_id = context.lcore_id,
		.queue_id = context.queue_id,
		.rx_received = context.rx_received,
		.rx_bytes = context.rx_bytes,
	};
}

fn WorkerStatsView make_worker_stats_view(WorkerContext* context) @private {
	WorkerStatsView view = {
		.worker_id = context.worker_id,
		.lcore_id = context.lcore_id,
		.queue_id = context.queue_id,
		.first_flow = context.first_flow,
		.flow_count = context.flow_count,
		.tx_attempted = context.tx_attempted,
		.tx_sent = context.tx_sent,
	};
	if (context.published_stats != null) {
		view.tx_attempted = context.published_stats.tx_attempted.load();
		view.tx_sent = context.published_stats.tx_sent.load();
	}
	return view;
}

fn RxWorkerStatsView make_rx_worker_stats_view(RxWorkerContext* context) @private {
	RxWorkerStatsView view = {
		.worker_id = context.worker_id,
		.lcore_id = context.lcore_id,
		.queue_id = context.queue_id,
		.rx_received = context.rx_received,
		.rx_bytes = context.rx_bytes,
	};
	if (context.published_stats != null) {
		view.rx_received = context.published_stats.rx_received.load();
		view.rx_bytes = context.published_stats.rx_bytes.load();
	}
	return view;
}

// --- live stats display ---------------------------------------------------

fn ulong counter_delta(ulong current, ulong previous) @private {
	return current >= previous ? current - previous : 0;
}

fn void print_live_stats(WorkerContext* tx_ctxs, usz tx_count, RxWorkerContext* rx_ctxs, usz rx_count, ushort port_id, usz packet_len, ushort batch_size, RunOptions options, LiveStatsState* state, long now) @private {
	@pool() {
		ulong elapsed = (ulong)(now - state.start);
		double sample_seconds = (double)(now - state.last);
		if (sample_seconds <= 0.0) sample_seconds = 1.0;
		state.last = now;

		ulong total_tx_sent = 0;
		ulong total_tx_attempted = 0;
		ulong total_tx_delta = 0;
		ulong[RUNTIME_MAX_LCORES] tx_deltas;
		for (usz i = 0; i < tx_count; i++) {
			WorkerStatsView worker = make_worker_stats_view(&tx_ctxs[i]);
			ulong delta = counter_delta(worker.tx_sent, state.previous_tx_sent[i]);
			state.previous_tx_sent[i] = worker.tx_sent;
			tx_deltas[i] = delta;
			total_tx_sent += worker.tx_sent;
			total_tx_attempted += worker.tx_attempted;
			total_tx_delta += delta;
		}

		ulong total_rx_received = 0;
		ulong total_rx_bytes = 0;
		ulong total_rx_delta = 0;
		ulong[RUNTIME_MAX_LCORES] rx_deltas;
		for (usz i = 0; i < rx_count; i++) {
			RxWorkerStatsView worker = make_rx_worker_stats_view(&rx_ctxs[i]);
			ulong delta = counter_delta(worker.rx_received, state.previous_rx_received[i]);
			state.previous_rx_received[i] = worker.rx_received;
			rx_deltas[i] = delta;
			total_rx_received += worker.rx_received;
			total_rx_bytes += worker.rx_bytes;
			total_rx_delta += delta;
		}

		double total_tx_pps = (double)total_tx_delta / sample_seconds;
		double total_tx_bps = total_tx_pps * (double)packet_len * 8.0;
		double total_rx_pps = (double)total_rx_delta / sample_seconds;
		double total_rx_bps = total_rx_pps * (double)packet_len * 8.0;

		EthStats stats;
		stats = {};
		(void)dpdk::ff_eth_stats_get(port_id, &stats);
		ulong imiss_delta = counter_delta(stats.imissed, state.previous_imissed);
		ulong ierrors_delta = counter_delta(stats.ierrors, state.previous_ierrors);
		state.previous_imissed = stats.imissed;
		state.previous_ierrors = stats.ierrors;

		io::printf("\033[2J\033[H");
		io::printn("FlowForge live stats\n");
		io::printfn("elapsed: %s", stats_format::format_elapsed_seconds(elapsed));
		io::printfn("packet_len: %d bytes", packet_len);
		io::printfn("tx_queues: %d    rx_queues: %d", tx_count, rx_count);
		io::printfn("tx_batch_size: %d    clone_count: %d", batch_size, options.clone_count);
		io::printfn("split: %s      once: %s\n", options.split ? "on" : "off", options.once ? "on" : "off");

		if (tx_count > 0) {
			io::printn("tx workers:");
			io::printfn("  %-4s%-8s%-8s%-14s%-14s%-14s%-12s%s", "id", "lcore", "queue", "flows", "sent", "attempted", "pps", "bps");
			for (usz i = 0; i < tx_count; i++) {
				WorkerStatsView worker = make_worker_stats_view(&tx_ctxs[i]);
				double worker_pps = (double)tx_deltas[i] / sample_seconds;
				double worker_bps = worker_pps * (double)packet_len * 8.0;
				io::printfn("  %-4d%-8d%-8d%-14s%-14s%-14s%-12s%s",
					worker.worker_id,
					worker.lcore_id,
					worker.queue_id,
					string::tformat("%d+%d", worker.first_flow, worker.flow_count),
					stats_format::format_human_count((double)worker.tx_sent),
					stats_format::format_human_count((double)worker.tx_attempted),
					stats_format::format_human_rate(worker_pps, "pps"),
					stats_format::format_human_rate(worker_bps, "bps"));
			}
			io::printfn("  tx total: %s packets, %s, %s\n",
				stats_format::format_human_count((double)total_tx_sent),
				stats_format::format_human_rate(total_tx_pps, "pps"),
				stats_format::format_human_rate(total_tx_bps, "bps"));
		}

		if (rx_count > 0) {
			io::printn("rx workers:");
			io::printfn("  %-4s%-8s%-8s%-14s%-14s%-12s%-12s%s", "id", "lcore", "queue", "received", "bytes", "pps", "bps", "imiss");
			for (usz i = 0; i < rx_count; i++) {
				RxWorkerStatsView worker = make_rx_worker_stats_view(&rx_ctxs[i]);
				double worker_pps = (double)rx_deltas[i] / sample_seconds;
				double worker_bps = worker_pps * (double)packet_len * 8.0;
				io::printfn("  %-4d%-8d%-8d%-14s%-14s%-12s%-12s%s",
					worker.worker_id,
					worker.lcore_id,
					worker.queue_id,
					stats_format::format_human_count((double)worker.rx_received),
					stats_format::format_human_count((double)worker.rx_bytes),
					stats_format::format_human_rate(worker_pps, "pps"),
					stats_format::format_human_rate(worker_bps, "bps"),
					stats_format::format_human_count((double)stats.imissed));
			}
			io::printfn("  rx total: %s packets, %s bytes, %s, %s, imiss: %s, errors: %s\n",
				stats_format::format_human_count((double)total_rx_received),
				stats_format::format_human_count((double)total_rx_bytes),
				stats_format::format_human_rate(total_rx_pps, "pps"),
				stats_format::format_human_rate(total_rx_bps, "bps"),
				stats_format::format_human_count((double)imiss_delta),
				stats_format::format_human_count((double)ierrors_delta));
		}
	};
}

fn bool wait_for_all(uint* lcores, WorkerContext* tx_ctxs, usz tx_launched, RxWorkerContext* rx_ctxs, usz rx_launched, ushort port_id, usz packet_len, ushort batch_size, RunOptions options, List{String}* errors) @private {
	usz total = tx_launched + rx_launched;
	bool ok = true;

	if (!options.stats_interval_seconds.has_value) {
		for (usz i = 0; i < total; i++) {
			int rc = dpdk::rte_eal_wait_lcore(lcores[i]);
			if (rc != 0) {
				ok = false;
				errors.push(string::tformat("worker on lcore %d failed with code %d", lcores[i], rc));
			}
		}
		return ok;
	}

	ulong interval = options.stats_interval_seconds.value;
	bool[RUNTIME_MAX_LCORES] joined;
	usz joined_count = 0;
	uint wait_state = dpdk::ff_lcore_wait_state();
	LiveStatsState state;
	state = {};
	state.start = time(null);
	state.last = state.start;
	state.next = state.start + (long)interval;

	while (joined_count < total) {
		long now = time(null);
		if (now >= state.next) {
			print_live_stats(tx_ctxs, tx_launched, rx_ctxs, rx_launched, port_id, packet_len, batch_size, options, &state, now);
			while (state.next <= now) state.next += (long)interval;
		}

		for (usz i = 0; i < total; i++) {
			if (joined[i]) continue;
			if (dpdk::rte_eal_get_lcore_state((uint)lcores[i]) != (int)wait_state) continue;
			int rc = dpdk::rte_eal_wait_lcore(lcores[i]);
			joined[i] = true;
			joined_count++;
			if (rc != 0) {
				ok = false;
				errors.push(string::tformat("worker on lcore %d failed with code %d", lcores[i], rc));
			}
		}

		if (joined_count < total) usleep(25000);
	}
	return ok;
}

// --- traffic orchestration ------------------------------------------------

fn bool run_traffic(ushort port_id, Mempool* mbuf_pool, PacketGenerator* generator, GeneratedPacket* packet, ushort batch_size, ulong tx_threads, ulong rx_threads, RunOptions options, List{String}* errors, Result* result, List{WorkerResult}* workers, List{WorkerResult}* rx_workers) @private {
	uint[RUNTIME_MAX_LCORES] lcore_buf;
	uint nworkers = dpdk::ff_worker_lcores(&lcore_buf[0], (uint)RUNTIME_MAX_LCORES);
	ulong total_threads = tx_threads + rx_threads;

	// Main-lcore fallback: `-l 0` provides no worker lcores. Transmit the single
	// TX worker on the calling thread so the common single-core case still runs.
	if (nworkers == 0 && rx_threads == 0 && tx_threads == 1) {
		WorkerContext context;
		context.errors.init(mem);
		defer context.errors.free();
		context.worker_id = 0;
		context.lcore_id = dpdk::ff_lcore_id();
		context.port_id = port_id;
		context.queue_id = 0;
		context.first_flow = 0;
		context.flow_count = packet.flow_plan.planned_packets;
		context.clone_count = options.clone_count;
		context.once = options.once;
		context.split = options.split;
		context.mbuf_pool = mbuf_pool;
		context.generator = generator;
		context.packet = packet;
		context.batch_size = batch_size;

		// Called on the main thread, which already owns a temp allocator, so run
		// the impls directly (the `@pool_init` wrappers are only for lcore threads).
		int rc = options.once ? run_worker_once_impl(&context) : run_worker_impl(&context);
		result.tx_attempted += context.tx_attempted;
		result.tx_sent += context.tx_sent;
		workers.push(make_worker_result(&context));
		foreach (e : context.errors) errors.push(e);
		return rc == 0;
	}

	if (nworkers < total_threads) {
		errors.push(string::tformat("PMD_THREADS(%d) + RX_THREADS(%d) requires %d worker lcore(s), but DPDK_ARGS enabled %d; use DPDK_ARGS like \"-l 0-%d\"",
			tx_threads, rx_threads, total_threads, nworkers, total_threads));
		return false;
	}

	WorkerContext[RUNTIME_MAX_LCORES] tx_ctxs;
	RxWorkerContext[RUNTIME_MAX_LCORES] rx_ctxs;
	PublishedWorkerStats[RUNTIME_MAX_LCORES] tx_published_stats;
	PublishedRxWorkerStats[RUNTIME_MAX_LCORES] rx_published_stats;
	uint[RUNTIME_MAX_LCORES] used_lcores;
	usz tx_launched = 0;
	usz rx_launched = 0;
	bool ok = true;

	for (ulong worker = 0; worker < tx_threads; worker++) {
		WorkerContext* context = &tx_ctxs[worker];
		*context = {};
		context.errors.init(mem);
		context.worker_id = worker;
		context.lcore_id = lcore_buf[worker];
		context.port_id = port_id;
		context.queue_id = (ushort)worker;
		FlowRange range = assigned_flow_range(packet.flow_plan.planned_packets, tx_threads, worker, options.split);
		context.first_flow = range.first;
		context.flow_count = range.count;
		context.clone_count = options.clone_count;
		context.once = options.once;
		context.split = options.split;
		context.mbuf_pool = mbuf_pool;
		context.generator = generator;
		context.packet = packet;
		context.batch_size = batch_size;
		context.published_stats = &tx_published_stats[worker];
		publish_worker_stats(context);

		LcoreFunction worker_fn = options.once ? &run_worker_once : &run_worker;
		int rc = dpdk::rte_eal_remote_launch(worker_fn, context, lcore_buf[worker]);
		if (rc < 0) {
			errors.push(string::tformat("rte_eal_remote_launch failed for TX lcore %d: %s", lcore_buf[worker], dpdk::strerror(-rc)));
			ok = false;
			break;
		}
		used_lcores[tx_launched] = lcore_buf[worker];
		tx_launched++;
	}

	if (ok) {
		for (ulong worker = 0; worker < rx_threads; worker++) {
			RxWorkerContext* context = &rx_ctxs[worker];
			*context = {};
			context.worker_id = worker;
			context.lcore_id = lcore_buf[tx_threads + worker];
			context.port_id = port_id;
			context.queue_id = (ushort)worker;
			context.batch_size = RUNTIME_RX_BATCH_SIZE;
			context.published_stats = &rx_published_stats[worker];
			publish_rx_worker_stats(context);

			int rc = dpdk::rte_eal_remote_launch(&run_rx_worker, context, lcore_buf[tx_threads + worker]);
			if (rc < 0) {
				errors.push(string::tformat("rte_eal_remote_launch failed for RX lcore %d: %s", lcore_buf[tx_threads + worker], dpdk::strerror(-rc)));
				ok = false;
				break;
			}
			used_lcores[tx_launched + rx_launched] = lcore_buf[tx_threads + worker];
			rx_launched++;
		}
	}

	if (!ok) runtime_stop_requested = true;

	ok = wait_for_all(&used_lcores[0], &tx_ctxs[0], tx_launched, &rx_ctxs[0], rx_launched, port_id, packet.packet_len, batch_size, options, errors) && ok;

	for (usz i = 0; i < tx_launched; i++) {
		result.tx_attempted += tx_ctxs[i].tx_attempted;
		result.tx_sent += tx_ctxs[i].tx_sent;
		workers.push(make_worker_result(&tx_ctxs[i]));
		foreach (e : tx_ctxs[i].errors) errors.push(e);
		tx_ctxs[i].errors.free();
	}
	for (usz i = 0; i < rx_launched; i++) {
		result.rx_received += rx_ctxs[i].rx_received;
		result.rx_bytes += rx_ctxs[i].rx_bytes;
		rx_workers.push(make_rx_worker_result(&rx_ctxs[i]));
	}
	return ok;
}

fn void capture_rx_workers(ulong rx_threads, List{String}* errors, Result* result, List{WorkerResult}* rx_workers) @private {
	uint[RUNTIME_MAX_LCORES] lcores;
	uint nworkers = dpdk::ff_worker_lcores(&lcores[0], (uint)RUNTIME_MAX_LCORES);
	if (nworkers < rx_threads) {
		errors.push(string::tformat("RX_THREADS(%d) requires %d worker lcore(s), but DPDK_ARGS enabled %d; use DPDK_ARGS like \"-l 0-%d\"",
			rx_threads, rx_threads, nworkers, rx_threads));
		return;
	}

	RxWorkerContext[RUNTIME_MAX_LCORES] ctxs;
	usz launched = 0;
	bool ok = true;

	for (ulong worker = 0; worker < rx_threads; worker++) {
		RxWorkerContext* context = &ctxs[worker];
		*context = {};
		context.worker_id = worker;
		context.lcore_id = lcores[worker];
		context.port_id = RUNTIME_PORT_ID;
		context.queue_id = (ushort)worker;
		context.batch_size = RUNTIME_RX_BATCH_SIZE;

		int rc = dpdk::rte_eal_remote_launch(&run_rx_worker, context, lcores[worker]);
		if (rc < 0) {
			errors.push(string::tformat("rte_eal_remote_launch failed for RX lcore %d: %s", lcores[worker], dpdk::strerror(-rc)));
			ok = false;
			break;
		}
		launched++;
	}

	if (!ok) runtime_stop_requested = true;
	for (usz worker = 0; worker < launched; worker++) {
		(void)dpdk::rte_eal_wait_lcore(lcores[worker]);
	}
	for (usz worker = 0; worker < launched; worker++) {
		result.rx_received += ctxs[worker].rx_received;
		result.rx_bytes += ctxs[worker].rx_bytes;
		rx_workers.push(make_rx_worker_result(&ctxs[worker]));
	}
}

// --- public entry points --------------------------------------------------

<* Initialises the EAL for a checked program (mirrors C++ Runtime::init). *>
fn Result Runtime.init(&self, Program program, String eal_program_name) {
	Result result;
	result.clone_count = 1;

	Config? config_opt = build_config(program, &result, default_run_options());
	if (catch config_opt) return result;
	Config config = config_opt;

	List{String} warnings;
	warnings.tinit();
	append_strings(&warnings, result.warnings);
	List{String} errors;
	errors.tinit();
	append_strings(&errors, result.errors);

	if (config.has_packet) {
		Checker checker = { .registry = self.registry };
		CheckResult check = checker.check(config.packet);
		append_strings(&warnings, check.warnings);
		append_strings(&errors, check.errors);
		if (!check.ok) {
			result.warnings = warnings.to_tarray();
			result.errors = errors.to_tarray();
			return result;
		}
	}

	if (init_eal(config.dpdk_args, eal_program_name, &result, &errors) < 0) {
		result.warnings = warnings.to_tarray();
		result.errors = errors.to_tarray();
		result.ok = false;
		return result;
	}

	result.warnings = warnings.to_tarray();
	result.errors = errors.to_tarray();
	result.ok = errors.len() == 0;
	return result;
}

<* Runs the live DPDK pipeline (TX or capture), mirroring C++ Runtime::run. *>
fn Result Runtime.run(&self, Program program, String eal_program_name, RunOptions options = default_run_options()) {
	Result result;
	result.clone_count = 1;

	Config? config_opt = build_config(program, &result, options);
	if (catch config_opt) return result;
	Config config = config_opt;

	List{String} warnings;
	warnings.tinit();
	append_strings(&warnings, result.warnings);
	List{String} errors;
	errors.tinit();
	append_strings(&errors, result.errors);
	List{WorkerResult} workers;
	workers.tinit();
	List{WorkerResult} rx_workers;
	rx_workers.tinit();

	if (options.capture) {
		run_capture(config, eal_program_name, options, &result, &warnings, &errors, &rx_workers);
		result.rx_workers = rx_workers.to_tarray();
		result.warnings = warnings.to_tarray();
		result.errors = errors.to_tarray();
		return result;
	}

	PacketGenerator generator = { .registry = self.registry };
	PacketGenerationResult generated = generator.prepare(config.packet, config.packet_count, live_fixup_options(), mem);
	append_strings(&warnings, generated.warnings);
	append_strings(&errors, generated.errors);
	if (!generated.ok || !generated.has_packet) {
		result.warnings = warnings.to_tarray();
		result.errors = errors.to_tarray();
		return result;
	}
	defer generated.packet.free();

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

	result.errors = errors.to_tarray();
	result.planned_transmissions = checked_total_transmission_count(result.planned_packets, result.pmd_threads, options, &result);
	errors.clear();
	append_strings(&errors, result.errors);
	if (errors.len()) {
		result.warnings = warnings.to_tarray();
		result.errors = errors.to_tarray();
		return result;
	}

	if (!check_tap_permission(&errors)) {
		result.warnings = warnings.to_tarray();
		result.errors = errors.to_tarray();
		result.ok = false;
		return result;
	}

	if (init_eal(config.dpdk_args, eal_program_name, &result, &errors) < 0) {
		result.warnings = warnings.to_tarray();
		result.errors = errors.to_tarray();
		result.ok = false;
		return result;
	}

	ulong tx_threads = result.pmd_threads;
	ulong rx_threads = result.rx_threads;
	ushort tx_queue_count = (ushort)tx_threads;
	ushort rx_queue_count = rx_threads > 0 ? (ushort)rx_threads : tx_queue_count;
	ushort batch_size = (ushort)config.tx_batch_size;

	install_signal_handlers();

	bool port_started = false;
	Mempool* pool = make_mbuf_pool(&generated.packet, tx_threads, batch_size, &errors);
	if (pool != null && probe_tap_port(&errors) &&
		configure_and_start_port(RUNTIME_PORT_ID, rx_queue_count, tx_queue_count, pool, &errors, &result)) {
		port_started = true;
		run_traffic(RUNTIME_PORT_ID, pool, &generator, &generated.packet, batch_size, tx_threads, rx_threads, options, &errors, &result, &workers, &rx_workers);
	}

	if (port_started) {
		EthStats stats;
		if (dpdk::ff_eth_stats_get(RUNTIME_PORT_ID, &stats) == 0) {
			result.rx_missed = stats.imissed;
			result.rx_errors = stats.ierrors;
		}
		stop_and_close_port(RUNTIME_PORT_ID, &warnings);
	}

	if (pool != null) dpdk::rte_mempool_free(pool);
	cleanup_eal(&warnings);

	result.workers = workers.to_tarray();
	result.rx_workers = rx_workers.to_tarray();
	result.warnings = warnings.to_tarray();
	result.errors = errors.to_tarray();
	result.ok = errors.len() == 0;
	return result;
}

fn void run_capture(Config config, String eal_program_name, RunOptions options, Result* result, List{String}* warnings, List{String}* errors, List{WorkerResult}* rx_workers) @private {
	result.pmd_threads = config.pmd_threads.has_value ? config.pmd_threads.value : 1;
	result.rx_threads = config.rx_threads.has_value ? config.rx_threads.value : 0;
	result.tx_batch_size = config.tx_batch_size;

	if (!check_tap_permission(errors)) {
		result.ok = false;
		return;
	}
	if (init_eal(config.dpdk_args, eal_program_name, result, errors) < 0) {
		result.ok = false;
		return;
	}

	ulong rx_threads = result.rx_threads;
	install_signal_handlers();

	Mempool* pool = dpdk::rte_pktmbuf_pool_create(
		zstr("packet_capture_mbuf_pool"),
		RUNTIME_CAPTURE_MBUF_COUNT,
		RUNTIME_MBUF_CACHE_SIZE,
		0,
		(ushort)dpdk::ff_mbuf_default_buf_size(),
		(int)dpdk::rte_socket_id());
	if (pool == null) {
		errors.push(string::tformat("rte_pktmbuf_pool_create failed: %s", dpdk::strerror(dpdk::ff_rte_errno())));
		cleanup_eal(warnings);
		result.ok = false;
		return;
	}

	bool have_file = false;
	File out;
	PcapWriter writer;
	if (options.capture_file.has_value) {
		File? opened = file::open(options.capture_file.value, "wb");
		if (catch opened) {
			errors.push(string::tformat("failed to open capture file '%s'", options.capture_file.value));
			dpdk::rte_mempool_free(pool);
			cleanup_eal(warnings);
			result.ok = false;
			return;
		}
		out = opened;
		have_file = true;
		writer = { .output = &out };
		PcapWriteResult header = writer.write_header();
		if (!header.ok) {
			foreach (e : header.errors) errors.push(e);
			(void)out.close();
			dpdk::rte_mempool_free(pool);
			cleanup_eal(warnings);
			result.ok = false;
			return;
		}
	}

	ushort tx_queue_count = 1;
	ushort rx_queue_count = rx_threads > 0 ? (ushort)rx_threads : 1;
	bool port_started = false;

	if (probe_tap_port(errors) &&
		configure_and_start_port(RUNTIME_PORT_ID, rx_queue_count, tx_queue_count, pool, errors, result)) {
		port_started = true;

		if (have_file) {
			Mbuf*[RUNTIME_MAX_RX_BATCH_SIZE] mbufs;
			while (!runtime_stop_requested) {
				ushort nb_rx = dpdk::ff_eth_rx_burst(RUNTIME_PORT_ID, 0, &mbufs[0], RUNTIME_RX_BATCH_SIZE);
				if (nb_rx == 0) continue;

				ulong bytes = 0;
				bool write_error = false;
				for (ushort i = 0; i < nb_rx; i++) {
					char* data = mbufs[i].mtod();
					uint len = mbufs[i].pkt_len;
					PcapWriteResult record = writer.write_packet(data[:len]);
					if (!record.ok) {
						foreach (e : record.errors) errors.push(e);
						write_error = true;
						break;
					}
					bytes += len;
				}

				result.rx_received += nb_rx;
				result.rx_bytes += bytes;
				dpdk::ff_pktmbuf_free_bulk(&mbufs[0], nb_rx);
				if (write_error) break;
			}
		} else if (rx_threads == 0) {
			RxWorkerContext context;
			context = {};
			context.worker_id = 0;
			context.lcore_id = dpdk::ff_lcore_id();
			context.port_id = RUNTIME_PORT_ID;
			context.queue_id = 0;
			context.batch_size = RUNTIME_RX_BATCH_SIZE;
			// Main thread already owns a temp allocator; call the impl directly.
			run_rx_worker_impl(&context);
			result.rx_received += context.rx_received;
			result.rx_bytes += context.rx_bytes;
			rx_workers.push(make_rx_worker_result(&context));
		} else {
			capture_rx_workers(rx_threads, errors, result, rx_workers);
		}
	}

	if (port_started) {
		EthStats stats;
		if (dpdk::ff_eth_stats_get(RUNTIME_PORT_ID, &stats) == 0) {
			result.rx_missed = stats.imissed;
			result.rx_errors = stats.ierrors;
		}
		stop_and_close_port(RUNTIME_PORT_ID, warnings);
	}

	if (have_file) (void)out.close();
	dpdk::rte_mempool_free(pool);
	cleanup_eal(warnings);
	result.ok = errors.len() == 0;
}

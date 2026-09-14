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
import std::collections::maybe;
import std::io;
import std::io::file;

// --- runtime constants (mirror runtime.cpp) -------------------------------

const ushort RUNTIME_RX_DESCRIPTORS = 128;
const ushort RUNTIME_TX_DESCRIPTORS = 512;
const uint RUNTIME_MBUF_CACHE_SIZE = 250;
const ushort RUNTIME_RX_BATCH_SIZE = 32;
const ushort RUNTIME_MAX_RX_BATCH_SIZE = 128;
const uint RUNTIME_CAPTURE_MBUF_COUNT = 8191;
const usz RUNTIME_MAX_LCORES = 128;
const usz RUNTIME_CACHE_LINE_SIZE = 64;
const usz RUNTIME_DRIVER_NAME_SIZE = 128;
const ushort RUNTIME_TX_RETRIES = 8;

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
	Atomic{ulong} tx_errors;
	char[40] _pad;
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
	GeneratedPacket* packet;
	ushort batch_size;
	ulong tx_attempted;
	ulong tx_sent;
	ulong tx_errors;
	PublishedWorkerStats* published_stats;
	List{String} warnings;
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
	ushort port_id;
	ulong worker_id;
	ulong lcore_id;
	ushort queue_id;
	ulong first_flow;
	ulong flow_count;
	ulong tx_attempted;
	ulong tx_sent;
	ulong tx_errors;
}

struct RxWorkerStatsView {
	ushort port_id;
	ulong worker_id;
	ulong lcore_id;
	ushort queue_id;
	ulong rx_received;
	ulong rx_bytes;
}

struct LiveStatsState {
	ulong[RUNTIME_MAX_LCORES] previous_tx_sent;
	ulong[RUNTIME_MAX_LCORES] previous_rx_received;
	ulong[RUNTIME_MAX_LCORES] previous_rx_bytes;
	ulong[RUNTIME_MAX_LCORES] previous_imissed;
	ulong[RUNTIME_MAX_LCORES] previous_ierrors;
	long start;
	long last;
	long next;
}

struct FlowRange {
	ulong first;
	ulong count;
}

struct SeedContext {
	char[] base;
	PacketOffloadRequest offload;
	uint seeded;
}

struct SeedAuditContext {
	char[] base;
	File* output;
	uint checked;
	uint mismatches;
	uint first_mismatch_index;
	usz first_mismatch_offset;
	bool write_failed;
	bool validate_payload;
}

// Binary seed-dump layout (all integer fields are little-endian):
//   header: magic[8], version:u32, endian:u32, mbuf_size:u32,
//           payload_size:u32, record_count:u32, record_size:u32
//   record: object_index:u32, raw rte_mbuf[mbuf_size], payload[payload_size]
// Pointer values in the raw mbuf are meaningful only in the producing process.
const uint MBUF_DUMP_VERSION = 1;
const uint MBUF_DUMP_ENDIAN_MARKER = 0x01020304;

// --- offload --------------------------------------------------------------

<* Applies a hardware-checksum offload request directly to an mbuf. DPDK flag
   values are compile-time constants so the per-packet path stays in C3. *>
fn void apply_dpdk_offload(Mbuf* mbuf, PacketOffloadRequest request) {
	assert(request.l2_len <= ushort::max && request.l3_len <= ushort::max &&
		request.l4_len <= ushort::max && request.outer_l2_len <= ushort::max &&
		request.outer_l3_len <= ushort::max, "DPDK offload lengths must fit in uint16_t");

	bool needs_l3 = request.ipv4_checksum || request.outer_ipv4_checksum ||
		request.tcp_checksum || request.udp_checksum || request.tunnel_vxlan;
	if (!needs_l3) return;

	mbuf.tx_offload.l2_len = request.l2_len;
	mbuf.tx_offload.l3_len = request.l3_len;
	mbuf.tx_offload.l4_len = request.l4_len;
	mbuf.tx_offload.outer_l2_len = request.outer_l2_len;
	mbuf.tx_offload.outer_l3_len = request.outer_l3_len;

	if (request.tunnel_vxlan) {
		mbuf.ol_flags &= ~dpdk::TX_TUNNEL_MASK;
		mbuf.ol_flags |= dpdk::TX_TUNNEL_VXLAN;
	}

	if (request.outer_ipv4_checksum) {
		mbuf.ol_flags |= dpdk::TX_OUTER_IPV4 | dpdk::TX_OUTER_IP_CKSUM;
	}

	if (request.layer3 == OffloadLayer3.IPV4 || request.ipv4_checksum) {
		mbuf.ol_flags |= dpdk::TX_IPV4;
	}
	else if (request.layer3 == OffloadLayer3.IPV6) {
		mbuf.ol_flags |= dpdk::TX_IPV6;
	}

	if (request.ipv4_checksum) {
		mbuf.ol_flags |= dpdk::TX_IP_CKSUM;
	}

	if (request.tcp_checksum || request.udp_checksum) {
		mbuf.ol_flags &= ~dpdk::TX_L4_MASK;
		mbuf.ol_flags |= request.tcp_checksum ? dpdk::TX_TCP_CKSUM : dpdk::TX_UDP_CKSUM;
	}
}

fn uint requested_tx_offload_features(PacketOffloadRequest request) @private {
	uint features = 0;
	if (request.ipv4_checksum) features |= dpdk::FF_TX_OFFLOAD_IPV4_CKSUM;
	if (request.udp_checksum) features |= dpdk::FF_TX_OFFLOAD_UDP_CKSUM;
	if (request.tcp_checksum) features |= dpdk::FF_TX_OFFLOAD_TCP_CKSUM;
	if (request.outer_ipv4_checksum) features |= dpdk::FF_TX_OFFLOAD_OUTER_IPV4_CKSUM;
	return features;
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
	mem::copy(data, context.base.ptr, (sz)context.base.len);
	mbuf.data_len = (ushort)context.base.len;
	mbuf.pkt_len = (uint)context.base.len;
	mbuf.reset_offload();
	apply_dpdk_offload(mbuf, context.offload);
	context.seeded++;
}

fn bool write_dump_bytes(File* output, char[] bytes) @private {
	sz? written = output.write(bytes);
	if (catch written) return false;
	return written >= 0 && (usz)written == bytes.len;
}

fn bool write_dump_u32(File* output, uint value) @private {
	char[4] bytes = {
		(char)(value & 0xff),
		(char)((value >> 8) & 0xff),
		(char)((value >> 16) & 0xff),
		(char)((value >> 24) & 0xff),
	};
	return write_dump_bytes(output, bytes[..]);
}

fn bool write_mbuf_dump_header(File* output, uint payload_size, uint record_count) @private {
	char[8] magic = { 'F', 'F', 'M', 'B', 'U', 'F', '0', '1' };
	uint mbuf_size = (uint)Mbuf::size;
	uint record_size = 4 + mbuf_size + payload_size;
	return write_dump_bytes(output, magic[..]) &&
		write_dump_u32(output, MBUF_DUMP_VERSION) &&
		write_dump_u32(output, MBUF_DUMP_ENDIAN_MARKER) &&
		write_dump_u32(output, mbuf_size) &&
		write_dump_u32(output, payload_size) &&
		write_dump_u32(output, record_count) &&
		write_dump_u32(output, record_size);
}

fn void audit_seeded_mbuf(Mempool* pool, void* opaque, void* obj, uint index) @private {
	SeedAuditContext* context = opaque;
	Mbuf* mbuf = obj;
	char[] payload = ((char*)mbuf.buf_addr + dpdk::MBUF_DEFAULT_HEADROOM)[:context.base.len];

	usz mismatch_offset = usz::max;
	if (context.validate_payload) {
		for (usz offset = 0; offset < context.base.len; offset++) {
			if (payload[offset] != context.base[offset]) {
				mismatch_offset = offset;
				break;
			}
		}
	}
	if (mismatch_offset != usz::max) {
		if (context.mismatches == 0) {
			context.first_mismatch_index = index;
			context.first_mismatch_offset = mismatch_offset;
		}
		context.mismatches++;
	}

	if (context.output != null && !context.write_failed) {
		char[] raw_mbuf = ((char*)mbuf)[:Mbuf::size];
		context.write_failed = !write_dump_u32(context.output, index) ||
			!write_dump_bytes(context.output, raw_mbuf) ||
			!write_dump_bytes(context.output, payload);
	}
	context.checked++;
}

fn bool inspect_mbuf_pool(Mempool* pool, char[] base, uint expected_count, Maybe{String} dump_file, bool validate_payload, List{String}* errors) @private {
	File out;
	bool have_dump = false;

	if (dump_file.has_value) {
		File? opened = file::open(dump_file.value, "wb");
		if (catch opened) {
			errors.push(string::tformat("failed to open mempool seed dump '%s'", dump_file.value));
			return false;
		}
		out = opened;
		have_dump = true;
		if (!write_mbuf_dump_header(&out, (uint)base.len, expected_count)) {
			(void)out.close();
			errors.push(string::tformat("failed to write mempool seed dump '%s'", dump_file.value));
			return false;
		}
	}

	SeedAuditContext context = {
		.base = base,
		.output = have_dump ? &out : null,
		.validate_payload = validate_payload,
	};
	uint iterated = dpdk::rte_mempool_obj_iter(pool, &audit_seeded_mbuf, &context);
	if (have_dump) (void)out.close();

	if (iterated == 0 || iterated != expected_count || context.checked != iterated) {
		errors.push("failed to audit every seeded Tx mbuf");
		return false;
	}
	if (context.write_failed) {
		errors.push(string::tformat("failed while writing mempool seed dump '%s'", dump_file.value));
		return false;
	}
	if (validate_payload && context.mismatches != 0) {
		errors.push(string::tformat("Tx mempool seed validation found %d mismatched mbuf(s); first mismatch: object %d byte %d",
			context.mismatches, context.first_mismatch_index, context.first_mismatch_offset));
		return false;
	}
	if (have_dump) {
		io::printfn("dumped %d Tx mbuf record(s) to '%s'", context.checked, dump_file.value);
	}
	return true;
}

fn Mempool* make_tx_mbuf_pool(GeneratedPacket* packet, ulong worker_count, ushort batch_size, Maybe{String} dump_file, List{String}* errors) @private {
	Mempool* pool = dpdk::rte_pktmbuf_pool_create(
		zstr("ffg_tx_pool"),
		mbuf_count_for(worker_count, batch_size),
		RUNTIME_MBUF_CACHE_SIZE,
		0,
		(ushort)dpdk::MBUF_DEFAULT_BUF_SIZE,
		(int)dpdk::rte_socket_id());
	if (pool == null) {
		errors.push(string::tformat("rte_pktmbuf_pool_create failed: %s", dpdk::strerror(dpdk::ff_rte_errno())));
		return null;
	}

	SeedContext context = { .base = packet.base_payload, .offload = packet.fixup_plan.offload };
	uint iterated = dpdk::rte_mempool_obj_iter(pool, &seed_mbuf_base_payload, &context);
	if (iterated == 0 || context.seeded != iterated) {
		errors.push("failed to seed packet base payload into the mbuf pool");
		dpdk::rte_mempool_free(pool);
		return null;
	}
	Maybe{String} pre_dump_file;
	if (dump_file.has_value) pre_dump_file.set(string::tformat("%s.pre", dump_file.value));
	if (!inspect_mbuf_pool(pool, packet.base_payload, iterated, pre_dump_file, true, errors)) {
		dpdk::rte_mempool_free(pool);
		return null;
	}
	return pool;
}

fn Mempool* make_rx_mbuf_pool(ushort rx_queue_count, List{String}* errors) @private {
	ulong needed = (ulong)rx_queue_count * ((ulong)RUNTIME_RX_DESCRIPTORS + (ulong)RUNTIME_MAX_RX_BATCH_SIZE * 2) + RUNTIME_MBUF_CACHE_SIZE;
	if (needed < RUNTIME_CAPTURE_MBUF_COUNT) needed = RUNTIME_CAPTURE_MBUF_COUNT;
	Mempool* pool = dpdk::rte_pktmbuf_pool_create(
		zstr("ffg_rx_pool"),
		(uint)needed,
		RUNTIME_MBUF_CACHE_SIZE,
		0,
		(ushort)dpdk::MBUF_DEFAULT_BUF_SIZE,
		(int)dpdk::rte_socket_id());
	if (pool == null) {
		errors.push(string::tformat("Rx rte_pktmbuf_pool_create failed: %s", dpdk::strerror(dpdk::ff_rte_errno())));
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

fn bool init_port_driver_ops(String driver_name, ushort rx_queue_count, Result* result, dpdk::DriverOps* ops) @private @feat(XSL_DPDK) {
	if (!dpdk::is_xsl_driver(driver_name)) return true;
	uint mask_bits;
	if (!dpdk::rss_lb_mask_bits(rx_queue_count, &mask_bits)) {
		result.warnings.push(string::tformat(
			"XSL port requires a power-of-two RX queue count; got %d", rx_queue_count));
		result.ok = false;
		return false;
	}

	*ops = dpdk::alloc_xsl_driver(mask_bits);
	return true;
}

fn bool init_port_driver_ops(String driver_name, ushort rx_queue_count, Result* result, dpdk::DriverOps* ops) @private @feat(!XSL_DPDK) {
	return true;
}

fn void finish_live_port_run(Result* result, bool port_started) {
	result.ok = port_started && result.errors.len() == 0;
}

fn bool configure_and_start_port(ushort port_id, ushort rx_queue_count, ushort tx_queue_count, Mempool* mbuf_pool, uint tx_offload_features, List{String}* errors, Result* result) @private {
	ushort port_count = dpdk::rte_eth_dev_count_avail();
	if (port_count == 0) {
		errors.push("no DPDK ethdev ports are available");
		return false;
	}
	ushort[RUNTIME_MAX_LCORES] available;
	uint count = dpdk::ff_eth_port_ids(&available[0], (uint)RUNTIME_MAX_LCORES);
	bool found = false;
	for (uint i = 0; i < count && i < RUNTIME_MAX_LCORES; i++) {
		if (available[i] == port_id) found = true;
	}
	if (!found) {
		errors.push(string::tformat("requested DPDK port %d but only %d port(s) are available", port_id, port_count));
		return false;
	}

	char[RUNTIME_DRIVER_NAME_SIZE] driver_name_buffer;
	driver_name_buffer[0] = 0;
	int rc = dpdk::ff_eth_dev_driver_name(port_id, &driver_name_buffer[0], RUNTIME_DRIVER_NAME_SIZE);
	if (rc < 0) {
		errors.push(string::tformat("failed to get DPDK driver name for port %d: %s", port_id, dpdk::strerror(-rc)));
		return false;
	}
	String driver_name = ((ZString)&driver_name_buffer[0]).str_view();
	dpdk::DriverOps driver_ops = {};
	if (!init_port_driver_ops(driver_name, rx_queue_count, result, &driver_ops)) return false;
	defer {
		if (driver_ops != null) mem::free((void*)driver_ops);
	}

	rc = dpdk::ff_eth_dev_configure(port_id, rx_queue_count, tx_queue_count, tx_offload_features);
	if (rc < 0) {
		errors.push(string::tformat("rte_eth_dev_configure failed for port %d: %s", port_id, dpdk::strerror(-rc)));
		return false;
	}

	bool ready = false;
	defer {
		if (!ready) {
			(void)dpdk::rte_eth_dev_stop(port_id);
			(void)dpdk::rte_eth_dev_close(port_id);
		}
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
		rc = dpdk::ff_eth_tx_queue_setup(port_id, queue_id, RUNTIME_TX_DESCRIPTORS, (uint)socket, tx_offload_features);
		if (rc < 0) {
			errors.push(string::tformat("rte_eth_tx_queue_setup failed for port %d queue %d: %s", port_id, queue_id, dpdk::strerror(-rc)));
			return false;
		}
	}

	if (driver_ops != null) {
		rc = driver_ops.set_rss(port_id);
		if (rc < 0) {
			errors.push(string::tformat(
				"driver set_rss failed for port %d with %d RX queue(s): %s",
				port_id, rx_queue_count, dpdk::strerror(-rc)));
			return false;
		}
	}

	rc = dpdk::rte_eth_dev_start(port_id);
	if (rc < 0) {
		errors.push(string::tformat("rte_eth_dev_start failed for port %d: %s", port_id, dpdk::strerror(-rc)));
		return false;
	}

	rc = dpdk::rte_eth_promiscuous_enable(port_id);
	if (rc < 0) {
		errors.push(string::tformat("rte_eth_promiscuous_enable failed for port %d: %s", port_id, dpdk::strerror(-rc)));
		return false;
	}


	ready = true;
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
	char[] payload = mbuf.mtod()[:context.packet.base_payload.len];
	if (!context.packet.apply_flow_checksums_only_unchecked(flow_index, payload, &context.errors)) {
		return false;
	}

	return true;
}

fn bool has_flow_modifiers(GeneratedPacket* packet) @private => packet.modifiers.len() != 0;

fn int alloc_worker_mbufs(WorkerContext* context, Mbuf** batch, ushort count) @private {
	return dpdk::ff_pktmbuf_raw_alloc_bulk(context.mbuf_pool, batch, count);
}

fn void publish_worker_stats(WorkerContext* context) @private {
	if (context.published_stats == null) return;
	context.published_stats.tx_attempted.store(context.tx_attempted);
	context.published_stats.tx_sent.store(context.tx_sent);
	context.published_stats.tx_errors.store(context.tx_errors);
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
	ushort retries_remaining = RUNTIME_TX_RETRIES;
	while (sent_total < prepared) {
		ushort sent = dpdk::ff_eth_tx_burst(context.port_id, context.queue_id, &packets[sent_total], (ushort)(prepared - sent_total));
		sent_total += sent;
		if (sent_total == prepared) break;
		if (@unlikely(retries_remaining == 0)) {
			ushort unsent = prepared - sent_total;
			free_unsent(packets, sent_total, prepared);
			context.tx_errors += unsent;
			break;
		}
		retries_remaining--;
	}

	context.tx_sent += sent_total;
	return prepared == count;
}

// Worker messages are built with tmem but are read back by the main thread
// after the worker's pool is destroyed, so copy them onto the (main-owned) heap
// list before the pool unwinds.
fn void heapify_messages(List{String}* messages) @private {
	foreach (i, message : messages) {
		messages.set(i, message.copy(mem));
	}
}

fn int run_worker_once(void* arg) @private {
	WorkerContext* context = arg;
	int rc;
	@pool_init(mem, RUNTIME_WORKER_POOL_SIZE) {
		rc = run_worker_once_impl(context);
		heapify_messages(&context.warnings);
		heapify_messages(&context.errors);
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
		if (alloc_worker_mbufs(context, &batch[0], count) != 0) {
			context.warnings.push(string::tformat("ff_pktmbuf_raw_alloc_bulk failed for %d packet(s): %s", count, dpdk::strerror(dpdk::ff_rte_errno())));
			return 0;
		}

		if (has_flow_modifiers(context.packet)) {
			for (ushort i = 0; i < count; i++) {
				ulong flow_index = context.first_flow + (transmitted + i) / context.clone_count;
				if (!prepare_batch_packet(context, batch[i], flow_index)) {
					free_unsent(&batch[0], 0, count);
					return 1;
				}
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
		heapify_messages(&context.warnings);
		heapify_messages(&context.errors);
	};
	return rc;
}

fn int run_worker_impl(WorkerContext* context) @private {
	Mbuf*[RUNTIME_MAX_TX_BATCH_SIZE] batch;
	if (context.flow_count == 0) return 0;

	ulong global_transmission = 0;
	while (!runtime_stop_requested) {
		ushort count = context.batch_size;
		if (alloc_worker_mbufs(context, &batch[0], count) != 0) {
			context.warnings.push(string::tformat("ff_pktmbuf_raw_alloc_bulk failed for %d packet(s): %s", count, dpdk::strerror(dpdk::ff_rte_errno())));
			return 0;
		}

		if (has_flow_modifiers(context.packet)) {
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

fn FlowRange assigned_flow_range(ulong planned_flows, ulong worker_count, ulong worker_id, bool split) {
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
		.port_id = context.port_id,
		.queue_id = context.queue_id,
		.first_flow = context.first_flow,
		.flow_count = context.flow_count,
		.tx_attempted = context.tx_attempted,
		.tx_sent = context.tx_sent,
		.tx_errors = context.tx_errors,
	};
}

fn WorkerResult make_rx_worker_result(RxWorkerContext* context) @private {
	return {
		.worker_id = context.worker_id,
		.lcore_id = context.lcore_id,
		.port_id = context.port_id,
		.queue_id = context.queue_id,
		.rx_received = context.rx_received,
		.rx_bytes = context.rx_bytes,
	};
}

fn WorkerStatsView make_worker_stats_view(WorkerContext* context) @private {
	WorkerStatsView view = {
		.worker_id = context.worker_id,
		.lcore_id = context.lcore_id,
		.port_id = context.port_id,
		.queue_id = context.queue_id,
		.first_flow = context.first_flow,
		.flow_count = context.flow_count,
		.tx_attempted = context.tx_attempted,
		.tx_sent = context.tx_sent,
		.tx_errors = context.tx_errors,
	};
	if (context.published_stats != null) {
		view.tx_attempted = context.published_stats.tx_attempted.load();
		view.tx_sent = context.published_stats.tx_sent.load();
		view.tx_errors = context.published_stats.tx_errors.load();
	}
	return view;
}

fn RxWorkerStatsView make_rx_worker_stats_view(RxWorkerContext* context) @private {
	RxWorkerStatsView view = {
		.worker_id = context.worker_id,
		.lcore_id = context.lcore_id,
		.port_id = context.port_id,
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

fn void print_live_stats(WorkerContext[] tx_ctxs, RxWorkerContext[] rx_ctxs, ushort[] ports, usz packet_len, ushort batch_size, RunOptions options, LiveStatsState* state, long now) @private {
	@pool() {
		double seconds = (double)(now - state.last);
		if (seconds <= 0.0) seconds = 1.0;
		state.last = now;
		io::printf("\033[2J\033[H");
		io::printn("FlowForge live stats");
		io::printfn("elapsed: %s", stats_format::format_elapsed_seconds((ulong)(now - state.start)));
		io::printfn("packet_len: %d bytes", packet_len);
		io::printfn("tx_queues: %d    rx_queues: %d", tx_ctxs.len, rx_ctxs.len);
		io::printfn("tx_batch_size: %d    clone_count: %d", batch_size, options.clone_count);
		io::printfn("split: %s      once: %s", options.split ? "on" : "off", options.once ? "on" : "off");
		ulong all_tx = 0;
		ulong all_tx_errors = 0;
		ulong all_rx = 0;
		ulong all_bytes = 0;
		double all_tx_pps = 0;
		double all_rx_pps = 0;
		double all_rx_bps = 0;
		foreach (pi, port : ports) {
			ulong sent = 0;
			ulong tx_errors = 0;
			ulong received = 0;
			ulong bytes = 0;
			double tx_pps = 0;
			double rx_pps = 0;
			double rx_bps = 0;
			io::printfn("\nport %d:", port);
			io::printn("tx workers:");
			foreach (i, ctx : tx_ctxs) {
				if (ctx.port_id != port) continue;
				WorkerStatsView w = make_worker_stats_view(&tx_ctxs[i]);
				double pps = (double)counter_delta(w.tx_sent, state.previous_tx_sent[i]) / seconds;
				state.previous_tx_sent[i] = w.tx_sent;
				sent += w.tx_sent;
				tx_errors += w.tx_errors;
				tx_pps += pps;
				io::printfn("  id %d lcore %d queue %d flows %d+%d sent %d attempted %d tx_errors %d %s %s",
					w.worker_id, w.lcore_id, w.queue_id, w.first_flow, w.flow_count, w.tx_sent, w.tx_attempted, w.tx_errors,
					stats_format::format_human_rate(pps, "pps"), stats_format::format_human_rate(pps * (double)packet_len * 8.0, "bps"));
			}
			io::printfn("  tx total: %d packets, tx_errors: %d, %s, %s", sent, tx_errors, stats_format::format_human_rate(tx_pps, "pps"), stats_format::format_human_rate(tx_pps * (double)packet_len * 8.0, "bps"));
			io::printn("rx workers:");
			foreach (i, ctx : rx_ctxs) {
				if (ctx.port_id != port) continue;
				RxWorkerStatsView w = make_rx_worker_stats_view(&rx_ctxs[i]);
				double pps = (double)counter_delta(w.rx_received, state.previous_rx_received[i]) / seconds;
				double bps = (double)counter_delta(w.rx_bytes, state.previous_rx_bytes[i]) * 8.0 / seconds;
				state.previous_rx_received[i] = w.rx_received;
				state.previous_rx_bytes[i] = w.rx_bytes;
				received += w.rx_received;
				bytes += w.rx_bytes;
				rx_pps += pps;
				rx_bps += bps;
				io::printfn("  id %d lcore %d queue %d received %d bytes %d %s %s", w.worker_id, w.lcore_id, w.queue_id, w.rx_received, w.rx_bytes,
					stats_format::format_human_rate(pps, "pps"), stats_format::format_human_rate(bps, "bps"));
			}
			EthStats stats = {};
			ulong missed = 0;
			ulong errors = 0;
			if (dpdk::ff_eth_stats_get(port, &stats) == 0) {
				missed = counter_delta(stats.imissed, state.previous_imissed[pi]);
				errors = counter_delta(stats.ierrors, state.previous_ierrors[pi]);
				state.previous_imissed[pi] = stats.imissed;
				state.previous_ierrors[pi] = stats.ierrors;
			}
			io::printfn("  rx total: %d packets, %d bytes, %s, %s, imiss: %d, errors: %d", received, bytes,
				stats_format::format_human_rate(rx_pps, "pps"), stats_format::format_human_rate(rx_bps, "bps"), missed, errors);
			all_tx += sent;
			all_tx_errors += tx_errors;
			all_rx += received;
			all_bytes += bytes;
			all_tx_pps += tx_pps;
			all_rx_pps += rx_pps;
			all_rx_bps += rx_bps;
		}
		io::printfn("\noverall tx total: %d packets, tx_errors: %d, %s, %s", all_tx, all_tx_errors, stats_format::format_human_rate(all_tx_pps, "pps"), stats_format::format_human_rate(all_tx_pps * (double)packet_len * 8.0, "bps"));
		io::printfn("overall rx total: %d packets, %d bytes, %s, %s", all_rx, all_bytes, stats_format::format_human_rate(all_rx_pps, "pps"), stats_format::format_human_rate(all_rx_bps, "bps"));
	};
}

fn bool wait_for_all(uint[] lcores, WorkerContext[] tx_ctxs, RxWorkerContext[] rx_ctxs, ushort[] ports, usz packet_len, ushort batch_size, RunOptions options, List{String}* errors) @private {
	usz total = lcores.len;
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
	uint wait_state = dpdk::LCORE_WAIT_STATE;
	LiveStatsState state;
	state = {};
	state.start = time(null);
	state.last = state.start;
	state.next = state.start + (long)interval;

	while (joined_count < total) {
		long now = time(null);
		if (now >= state.next) {
			print_live_stats(tx_ctxs, rx_ctxs, ports, packet_len, batch_size, options, &state, now);
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

fn bool run_traffic(ushort[] ports, Mempool* mbuf_pool, GeneratedPacket* packet, ushort batch_size, ulong tx_threads, ulong rx_threads, RunOptions options, List{String}* errors, Result* result, List{WorkerResult}* workers, List{WorkerResult}* rx_workers) @private {
	uint[RUNTIME_MAX_LCORES] lcore_buf;
	uint nworkers = dpdk::ff_worker_lcores(&lcore_buf[0], (uint)RUNTIME_MAX_LCORES);
	ulong total_threads = tx_threads + rx_threads;

	// Main-lcore fallback: `-l 0` provides no worker lcores. Transmit the single
	// TX worker on the calling thread so the common single-core case still runs.
	if (nworkers == 0 && rx_threads == 0 && tx_threads == 1) {
		WorkerContext context;
		context.warnings.init(mem);
		context.errors.init(mem);
		defer context.warnings.free();
		defer context.errors.free();
		context.worker_id = 0;
		context.lcore_id = dpdk::ff_lcore_id();
		context.port_id = ports[0];
		context.queue_id = 0;
		context.first_flow = 0;
		context.flow_count = packet.flow_plan.planned_packets;
		context.clone_count = options.clone_count;
		context.once = options.once;
		context.split = options.split;
		context.mbuf_pool = mbuf_pool;
		context.packet = packet;
		context.batch_size = batch_size;

		// Called on the main thread, which already owns a temp allocator, so run
		// the impls directly (the `@pool_init` wrappers are only for lcore threads).
		int rc = options.once ? run_worker_once_impl(&context) : run_worker_impl(&context);
		result.tx_attempted += context.tx_attempted;
		result.tx_sent += context.tx_sent;
		result.tx_errors += context.tx_errors;
		workers.push(make_worker_result(&context));
		foreach (warning : context.warnings) result.warnings.push(warning);
		foreach (e : context.errors) errors.push(e);
		return rc == 0;
	}

	if (nworkers == 0 && tx_threads == 0 && rx_threads == 1 && ports.len == 1) {
		RxWorkerContext context = {};
		context.port_id = ports[0];
		context.lcore_id = dpdk::ff_lcore_id();
		context.batch_size = RUNTIME_RX_BATCH_SIZE;
		run_rx_worker_impl(&context);
		result.rx_received += context.rx_received;
		result.rx_bytes += context.rx_bytes;
		rx_workers.push(make_rx_worker_result(&context));
		return true;
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
		context.warnings.init(mem);
		context.errors.init(mem);
		context.worker_id = worker;
		context.lcore_id = lcore_buf[worker];
		WorkerAssignment assignment = assign_port_worker(ports, tx_threads, worker);
		context.port_id = assignment.port_id;
		context.queue_id = assignment.queue_id;
		FlowRange range = assigned_flow_range(packet.flow_plan.planned_packets, tx_threads / (ulong)ports.len, context.queue_id, options.split);
		context.first_flow = range.first;
		context.flow_count = range.count;
		context.clone_count = options.clone_count;
		context.once = options.once;
		context.split = options.split;
		context.mbuf_pool = mbuf_pool;
		context.packet = packet;
		context.batch_size = batch_size;
		context.published_stats = &tx_published_stats[worker];
		publish_worker_stats(context);

		LcoreFunction worker_fn = options.once ? &run_worker_once : &run_worker;
		int rc = dpdk::rte_eal_remote_launch(worker_fn, context, lcore_buf[worker]);
		if (rc < 0) {
			context.warnings.free();
			context.errors.free();
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
			WorkerAssignment assignment = assign_port_worker(ports, rx_threads, worker);
			context.port_id = assignment.port_id;
			context.queue_id = assignment.queue_id;
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

	ok = wait_for_all(used_lcores[:tx_launched + rx_launched], tx_ctxs[:tx_launched], rx_ctxs[:rx_launched], ports, packet.base_payload.len, batch_size, options, errors) && ok;

	for (usz i = 0; i < tx_launched; i++) {
		result.tx_attempted += tx_ctxs[i].tx_attempted;
		result.tx_sent += tx_ctxs[i].tx_sent;
		result.tx_errors += tx_ctxs[i].tx_errors;
		workers.push(make_worker_result(&tx_ctxs[i]));
		foreach (warning : tx_ctxs[i].warnings) result.warnings.push(warning);
		foreach (e : tx_ctxs[i].errors) errors.push(e);
		tx_ctxs[i].warnings.free();
		tx_ctxs[i].errors.free();
	}
	for (usz i = 0; i < rx_launched; i++) {
		result.rx_received += rx_ctxs[i].rx_received;
		result.rx_bytes += rx_ctxs[i].rx_bytes;
		rx_workers.push(make_rx_worker_result(&rx_ctxs[i]));
	}
	return ok;
}

// --- public entry points --------------------------------------------------

<* Initialises the EAL for a checked program (mirrors C++ Runtime::init). *>
fn Result Runtime.init(&self, Program program, String eal_program_name) {
	Result result;
	result.tinit();
	result.clone_count = 1;

	Config? config_opt = build_config(program, &result, default_run_options());
	if (catch config_opt) return result;
	Config config = config_opt;

	if (config.has_packet) {
		Checker checker = { .registry = self.registry };
		CheckResult check = checker.check(config.packet);
		append_strings(&result.warnings, check.warnings);
		append_strings(&result.errors, check.errors);
		if (!check.ok) {
			return result;
		}
	}

	if (init_eal(config.dpdk_args, eal_program_name, &result, &result.errors) < 0) {
		result.ok = false;
		return result;
	}

	result.ok = result.errors.len() == 0;
	return result;
}

<* Runs the live DPDK pipeline (TX or capture), mirroring C++ Runtime::run. *>
fn Result Runtime.run(&self, Program program, String eal_program_name, RunOptions options = default_run_options()) {
	Result result;
	result.tinit();
	result.clone_count = 1;

	Config? config_opt = build_config(program, &result, options);
	if (catch config_opt) return result;
	Config config = config_opt;

	List{WorkerResult} workers;
	workers.tinit();
	List{WorkerResult} rx_workers;
	rx_workers.tinit();

	if (options.capture) {
		run_capture(config, eal_program_name, options, &result, &rx_workers);
		result.rx_workers = rx_workers.to_tarray();
		return result;
	}

	PacketGenerator generator = { .registry = self.registry };
	PacketGenerationResult generated = generator.prepare(config.packet, config.packet_count, live_fixup_options(), mem);
	append_strings(&result.warnings, generated.warnings);
	append_strings(&result.errors, generated.errors);
	if (!generated.ok || !generated.has_packet) {
		return result;
	}
	defer generated.packet.free();

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

	result.planned_transmissions = checked_total_transmission_count(result.planned_packets, result.pmd_threads, options, &result);
	if (generated.packet.base_payload.len > (usz)dpdk::MBUF_DEFAULT_DATAROOM) {
		result.errors.push(string::tformat("packet length %d does not fit in a DPDK mbuf", generated.packet.base_payload.len));
	}
	if (result.errors.len()) {
		return result;
	}

	if (init_eal(config.dpdk_args, eal_program_name, &result, &result.errors) < 0) {
		result.ok = false;
		return result;
	}

	ushort[] ports = discover_ports(&result.errors);
	defer cleanup_eal(&result.warnings);
	if (ports.len == 0) return result;
	result.pmd_threads = config.pmd_threads.has_value ? config.pmd_threads.value : ports.len;
	if (!validate_port_workers(ports.len, result.pmd_threads, result.rx_threads, &result.errors) ||
		!validate_worker_lcores(result.pmd_threads, result.rx_threads, &result.errors)) return result;
	result.planned_transmissions = checked_total_transmission_count(result.planned_packets,
		result.pmd_threads, options, &result, ports.len);
	if (result.errors.len()) return result;
	ulong tx_threads = result.pmd_threads;
	ulong rx_threads = result.rx_threads;
	ushort tx_queue_count = (ushort)(tx_threads / (ulong)ports.len);
	ushort rx_queue_count = rx_threads > 0 ? (ushort)(rx_threads / (ulong)ports.len) : tx_queue_count;
	ushort batch_size = (ushort)config.tx_batch_size;

	install_signal_handlers();

	usz started = 0;
	Mempool* tx_pool = make_tx_mbuf_pool(&generated.packet, tx_threads, batch_size, options.mempool_seed_dump_file, &result.errors);
	Mempool* rx_pool = make_rx_mbuf_pool((ushort)(rx_queue_count * ports.len), &result.errors);
	uint tx_offload_features = requested_tx_offload_features(generated.packet.fixup_plan.offload);
	if (tx_pool != null && rx_pool != null) {
		foreach (port : ports) {
			if (!configure_and_start_port(port, rx_queue_count, tx_queue_count, rx_pool, tx_offload_features, &result.errors, &result)) break;
			started++;
		}
		if (started == ports.len) {
			run_traffic(ports, tx_pool, &generated.packet, batch_size, tx_threads, rx_threads, options, &result.errors, &result, &workers, &rx_workers);
		}
	}
	collect_port_results(ports[:started], &result, workers.to_tarray(), rx_workers.to_tarray(), ports.len);
	foreach (port : ports[:started]) stop_and_close_port(port, &result.warnings);
	if (options.mempool_seed_dump_file.has_value && tx_pool != null) {
		Maybe{String} post_dump_file;
		post_dump_file.set(string::tformat("%s.post", options.mempool_seed_dump_file.value));
		(void)inspect_mbuf_pool(tx_pool, generated.packet.base_payload,
			mbuf_count_for(tx_threads, batch_size), post_dump_file, false, &result.errors);
	}
	if (rx_pool != null) dpdk::rte_mempool_free(rx_pool);
	if (tx_pool != null) dpdk::rte_mempool_free(tx_pool);

	result.workers = workers.to_tarray();
	result.rx_workers = rx_workers.to_tarray();
	finish_live_port_run(&result, started == ports.len);
	return result;
}

fn void run_capture(Config config, String eal_program_name, RunOptions options, Result* result, List{WorkerResult}* rx_workers) @private {
	result.pmd_threads = 0;
	result.rx_threads = config.rx_threads.has_value ? config.rx_threads.value : 0;
	result.tx_batch_size = config.tx_batch_size;

	if (init_eal(config.dpdk_args, eal_program_name, result, &result.errors) < 0) {
		result.ok = false;
		return;
	}

	ushort[] ports = discover_ports(&result.errors);
	if (ports.len == 0) {
		cleanup_eal(&result.warnings);
		return;
	}
	if (options.capture_file.has_value && ports.len != 1) {
		result.errors.push("PCAP capture supports only one DPDK port");
		cleanup_eal(&result.warnings);
		return;
	}
	result.rx_threads = config.rx_threads.has_value ? config.rx_threads.value : ports.len;
	if (!validate_port_workers(ports.len, 0, result.rx_threads, &result.errors) ||
		(!options.capture_file.has_value && !validate_worker_lcores(0, result.rx_threads, &result.errors))) {
		cleanup_eal(&result.warnings);
		return;
	}
	if (!options.capture_file.has_value) {
		install_signal_handlers();
		ushort queues = (ushort)(result.rx_threads / (ulong)ports.len);
		Mempool* rx_pool = make_rx_mbuf_pool((ushort)result.rx_threads, &result.errors);
		usz started = 0;
		if (rx_pool != null) {
			foreach (port : ports) {
				if (!configure_and_start_port(port, queues, 1, rx_pool, 0, &result.errors, result)) break;
				started++;
			}
			if (started == ports.len) {
				GeneratedPacket empty_packet = {};
				List{WorkerResult} tx;
				tx.tinit();
				run_traffic(ports, null, &empty_packet, RUNTIME_RX_BATCH_SIZE, 0, result.rx_threads, options, &result.errors, result, &tx, rx_workers);
			}
		}
		collect_port_results(ports[:started], result, {}, rx_workers.to_tarray(), ports.len);
		foreach (port : ports[:started]) stop_and_close_port(port, &result.warnings);
		if (rx_pool != null) dpdk::rte_mempool_free(rx_pool);
		cleanup_eal(&result.warnings);
		finish_live_port_run(result, started == ports.len);
		return;
	}
	ulong rx_threads = result.rx_threads;
	install_signal_handlers();

	Mempool* pool = dpdk::rte_pktmbuf_pool_create(
		zstr("packet_capture_mbuf_pool"),
		RUNTIME_CAPTURE_MBUF_COUNT,
		RUNTIME_MBUF_CACHE_SIZE,
		0,
		(ushort)dpdk::MBUF_DEFAULT_BUF_SIZE,
		(int)dpdk::rte_socket_id());
	if (pool == null) {
		result.errors.push(string::tformat("rte_pktmbuf_pool_create failed: %s", dpdk::strerror(dpdk::ff_rte_errno())));
		cleanup_eal(&result.warnings);
		result.ok = false;
		return;
	}

	bool have_file = false;
	File out;
	PcapWriter writer;
	if (options.capture_file.has_value) {
		File? opened = file::open(options.capture_file.value, "wb");
		if (catch opened) {
			result.errors.push(string::tformat("failed to open capture file '%s'", options.capture_file.value));
			dpdk::rte_mempool_free(pool);
			cleanup_eal(&result.warnings);
			result.ok = false;
			return;
		}
		out = opened;
		have_file = true;
		writer = { .output = &out };
		PcapWriteResult header = writer.write_header();
		if (!header.ok) {
			foreach (e : header.errors) result.errors.push(e);
			(void)out.close();
			dpdk::rte_mempool_free(pool);
			cleanup_eal(&result.warnings);
			result.ok = false;
			return;
		}
	}

	ushort tx_queue_count = 1;
	ushort rx_queue_count = rx_threads > 0 ? (ushort)rx_threads : 1;
	bool port_started = false;

	if (configure_and_start_port(ports[0], rx_queue_count, tx_queue_count, pool, 0, &result.errors, result)) {
		port_started = true;

		if (have_file) {
			Mbuf*[RUNTIME_MAX_RX_BATCH_SIZE] mbufs;
			while (!runtime_stop_requested) {
				ushort nb_rx = dpdk::ff_eth_rx_burst(ports[0], 0, &mbufs[0], RUNTIME_RX_BATCH_SIZE);
				if (nb_rx == 0) continue;

				ulong bytes = 0;
				bool write_error = false;
				for (ushort i = 0; i < nb_rx; i++) {
					char* data = mbufs[i].mtod();
					uint len = mbufs[i].pkt_len;
					PcapWriteResult record = writer.write_packet(data[:len]);
					if (!record.ok) {
						foreach (e : record.errors) result.errors.push(e);
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
		}
	}

	if (port_started) {
		EthStats stats;
		if (dpdk::ff_eth_stats_get(ports[0], &stats) == 0) {
			result.rx_missed = stats.imissed;
			result.rx_errors = stats.ierrors;
		}
		stop_and_close_port(ports[0], &result.warnings);
	}

	result.ports = mem::temp_array(PortResult, 1);
	result.ports[0] = { .port_id = ports[0], .rx_received = result.rx_received, .rx_bytes = result.rx_bytes, .rx_missed = result.rx_missed, .rx_errors = result.rx_errors };
	if (have_file) (void)out.close();
	dpdk::rte_mempool_free(pool);
	cleanup_eal(&result.warnings);
	finish_live_port_run(result, port_started);
}

fn ushort[] discover_ports(List{String}* errors) @private {
	ushort[RUNTIME_MAX_LCORES] ids;
	uint count = dpdk::ff_eth_port_ids(&ids[0], (uint)RUNTIME_MAX_LCORES);
	if (count == 0) {
		if (!check_tap_permission(errors) || !probe_tap_port(errors)) return {};
		count = dpdk::ff_eth_port_ids(&ids[0], (uint)RUNTIME_MAX_LCORES);
	}
	if (count == 0 || count > RUNTIME_MAX_LCORES) {
		errors.push("available port count must be between 1 and 128");
		return {};
	}
	ushort[] ports = mem::temp_array(ushort, (sz)count);
	ports[..] = ids[:count];
	return ports;
}

fn void collect_port_results(ushort[] ports, Result* result, WorkerResult[] tx, WorkerResult[] rx, usz total_ports) @private {
	result.ports = mem::temp_array(PortResult, (sz)ports.len);
	foreach (i, port : ports) {
		PortResult* p = &result.ports[i];
		*p = summarize_port_workers(port, tx, rx);
		p.planned_transmissions = result.planned_transmissions / total_ports;
		EthStats stats = {};
		if (dpdk::ff_eth_stats_get(port, &stats) == 0) {
			p.rx_missed = stats.imissed;
			p.rx_errors = stats.ierrors;
			result.rx_missed += stats.imissed;
			result.rx_errors += stats.ierrors;
		}
	}
}

fn bool validate_worker_lcores(ulong tx, ulong rx, List{String}* errors) @private {
	uint[RUNTIME_MAX_LCORES] ids;
	uint count = dpdk::ff_worker_lcores(&ids[0], (uint)RUNTIME_MAX_LCORES);
	if (count == 0 && tx + rx == 1) return true;
	if (count < tx + rx) {
		errors.push(string::tformat("PMD_THREADS(%d) + RX_THREADS(%d) requires %d worker lcore(s), but DPDK_ARGS enabled %d", tx, rx, tx + rx, count));
		return false;
	}
	return true;
}

<* Thin C3 bindings for the DPDK runtime.

   Only the symbols the FlowForge live runtime needs are declared here. The
   exported `rte_*` functions are bound directly; everything that DPDK only
   offers through macros, thread-local variables or `static inline` helpers is
   reached through the C shim in `csrc/dpdk_shim.c` (the `ff_*` functions). *>
module flowforge::dpdk;

// The mbuf layout below assumes an LP64 target (64-bit pointers / rte_iova_t,
// RTE_IOVA_IN_MBUF set). Both of our target arches (x86-64, aarch64) share it.
// DPDK pins the second field group with `alignas(RTE_CACHE_LINE_MIN_SIZE)` (=64),
// so the offsets we touch don't move with the arch's real cache-line size. A
// per-arch `@if` variant can be added for a 32-bit target if ever needed; the
// runtime guard test `test_mbuf_layout_matches_dpdk` verifies these offsets
// against the real DPDK headers (catching build-config drift `@if` can't see).
$assert env::X86_64 || env::AARCH64 : "dpdk::Mbuf mirror assumes an LP64 target";

// tx_offload bitfield word (union member of struct rte_mbuf). Bit ranges match
// the little-endian gcc/clang packing of `uint64_t l2_len:7, l3_len:9, l4_len:8`.
bitstruct TxOffload : ulong {
	ulong l2_len    : 0..6;   // RTE_MBUF_L2_LEN_BITS = 7
	ulong l3_len    : 7..15;  // RTE_MBUF_L3_LEN_BITS = 9
	ulong l4_len    : 16..23; // RTE_MBUF_L4_LEN_BITS = 8
	ulong tso_segsz : 24..39; // RTE_MBUF_TSO_SEGSZ_BITS = 16
	ulong outer_l3_len : 40..48; // RTE_MBUF_OUTL3_LEN_BITS = 9
	ulong outer_l2_len : 49..55; // RTE_MBUF_OUTL2_LEN_BITS = 7
}

// C3 mirror of `struct rte_mbuf`. Only the offsets of the fields we access are
// load-bearing (we always hold Mbuf*, never Mbuf[] by value); the rest are
// opaque padding kept so the struct spans the two-cache-line footprint.
struct Mbuf @align(64) {
	void*     buf_addr;        // 0
	ulong     buf_iova;        // 8   (`next` when RTE_IOVA_IN_MBUF == 0; same size)
	ushort    data_off;        // 16
	ushort    refcnt;          // 18
	ushort    nb_segs;         // 20
	ushort    port;            // 22
	ulong     ol_flags;        // 24
	uint      packet_type;     // 32
	uint      pkt_len;         // 36
	ushort    data_len;        // 40
	ushort    vlan_tci;        // 42
	char[8]   _hash;           // 44  opaque
	ushort    vlan_tci_outer;  // 52
	ushort    buf_len;         // 54
	Mempool*  pool;            // 56  (first cache line ends at 64)
	void*     _next_or_dyn;    // 64
	TxOffload tx_offload;      // 72
	char[48]  _tail;           // 80..127 opaque
}

alias Mempool = void;

<* Data pointer for a single-segment mbuf: buf_addr + data_off. *>
fn char* Mbuf.mtod(&self) @inline => (char*)self.buf_addr + self.data_off;

<* Appends `len` bytes to a single-segment mbuf, returning the tail pointer, or
   null when there is not enough tailroom. Equivalent to rte_pktmbuf_append for
   nb_segs == 1, which is the only case the runtime produces. *>
fn char* Mbuf.append(&self, ushort len) @inline {
	assert(self.nb_segs == 1, "Mbuf.append only supports single-segment mbufs");
	ushort used = self.data_off + self.data_len;
	if (len > self.buf_len - used) return null;
	char* tail = (char*)self.buf_addr + used;
	self.data_len += len;
	self.pkt_len += len;
	return tail;
}

<* Clears the Tx checksum-offload metadata, matching the per-packet reset the
   C++ runtime performs before applying a fresh offload request. *>
fn void Mbuf.reset_offload(&self) @inline {
	self.ol_flags = 0;
	self.tx_offload.l2_len = 0;
	self.tx_offload.l3_len = 0;
	self.tx_offload.l4_len = 0;
	self.tx_offload.outer_l2_len = 0;
	self.tx_offload.outer_l3_len = 0;
}

alias LcoreFunction = fn int(void* arg);
alias MempoolObjCb = fn void(Mempool* pool, void* opaque, void* obj, uint index);

// Mirrors serializer::OffloadLayer3 / enum ff_offload_layer3 in the shim.
const int FF_OFFLOAD_L3_NONE = 0;
const int FF_OFFLOAD_L3_IPV4 = 1;
const int FF_OFFLOAD_L3_IPV6 = 2;

// DPDK Tx offload flags. These are stable mbuf flag bit assignments from
// rte_mbuf_core.h; keeping them here avoids shim calls on the per-packet path.
const ulong TX_IPV4 = 1ul << 55;
const ulong TX_IPV6 = 1ul << 56;
const ulong TX_IP_CKSUM = 1ul << 54;
const ulong TX_TCP_CKSUM = 1ul << 52;
const ulong TX_UDP_CKSUM = 3ul << 52;
const ulong TX_L4_MASK = 3ul << 52;
const ulong TX_TUNNEL_VXLAN = 1ul << 45;
const ulong TX_TUNNEL_MASK = 0xful << 45;
const ulong TX_OUTER_IP_CKSUM = 1ul << 58;
const ulong TX_OUTER_IPV4 = 1ul << 59;

// DPDK defaults from rte_mbuf_core.h / rte_config.h and rte_launch.h.
const uint MBUF_DEFAULT_BUF_SIZE = 2176; // 2048 dataroom + 128 headroom
const uint LCORE_WAIT_STATE = 0;

// Subset of rte_eth_stats read back by the runtime (matches struct ff_eth_stats).
struct EthStats {
	ulong ipackets;
	ulong opackets;
	ulong ibytes;
	ulong obytes;
	ulong imissed;
	ulong ierrors;
	ulong oerrors;
	ulong rx_nombuf;
}

// --- EAL / lcore (exported symbols) --------------------------------------
extern fn int rte_eal_init(int argc, char** argv);
extern fn int rte_eal_cleanup();
extern fn int rte_eal_remote_launch(LcoreFunction f, void* arg, uint worker_id);
extern fn int rte_eal_wait_lcore(uint worker_id);
extern fn int rte_eal_get_lcore_state(uint lcore_id);
extern fn uint rte_socket_id();
extern fn ZString rte_strerror(int errnum);
extern fn int rte_eal_hotplug_add(ZString busname, ZString devname, ZString devargs);

// --- ethdev (exported symbols) -------------------------------------------
extern fn ushort rte_eth_dev_count_avail();
extern fn int rte_eth_rx_queue_setup(ushort port_id, ushort rx_queue_id, ushort nb_rx_desc, uint socket_id, void* rx_conf, Mempool* mb_pool);
extern fn int rte_eth_tx_queue_setup(ushort port_id, ushort tx_queue_id, ushort nb_tx_desc, uint socket_id, void* tx_conf);
extern fn int rte_eth_dev_start(ushort port_id);
extern fn int rte_eth_dev_stop(ushort port_id);
extern fn int rte_eth_dev_close(ushort port_id);
extern fn int rte_eth_dev_socket_id(ushort port_id);

// --- mempool / mbuf pool (exported symbols) ------------------------------
extern fn Mempool* rte_pktmbuf_pool_create(ZString name, uint n, uint cache_size, ushort priv_size, ushort data_room_size, int socket_id);
extern fn void rte_mempool_free(Mempool* mp);
extern fn uint rte_mempool_obj_iter(Mempool* mp, MempoolObjCb cb, void* arg);

// --- shim: mbuf layout guard ---------------------------------------------
// Fills `out` with the real DPDK offsets/size so the C3 mirror above can be
// verified against the compiled headers. Order:
//   [0]=buf_addr [1]=data_off [2]=ol_flags [3]=pkt_len
//   [4]=data_len [5]=buf_len  [6]=tx_offload [7]=sizeof(struct rte_mbuf)
const usz FF_MBUF_LAYOUT_FIELDS = 8;
extern fn void ff_mbuf_layout(usz* out);

// --- shim: inline / thread-local DPDK operations -------------------------
extern fn int ff_rte_errno();
extern fn uint ff_lcore_id();
extern fn int ff_pktmbuf_alloc_bulk(Mempool* pool, Mbuf** mbufs, uint count);
extern fn void ff_pktmbuf_free(Mbuf* mbuf);
extern fn void ff_pktmbuf_free_bulk(Mbuf** mbufs, uint count);
extern fn ushort ff_eth_tx_burst(ushort port_id, ushort queue_id, Mbuf** tx_pkts, ushort nb_pkts);
extern fn ushort ff_eth_tx_prepare(ushort port_id, ushort queue_id, Mbuf** tx_pkts, ushort nb_pkts);
extern fn ushort ff_eth_rx_burst(ushort port_id, ushort queue_id, Mbuf** rx_pkts, ushort nb_pkts);
extern fn int ff_eth_dev_configure(ushort port_id, ushort nb_rx_q, ushort nb_tx_q);
extern fn int ff_eth_stats_get(ushort port_id, EthStats* out);

// --- shim: lcore enumeration / tap / test --------------------------------
extern fn uint ff_worker_lcores(uint* out, uint max);
extern fn Mbuf* ff_test_alloc_mbuf();
extern fn void ff_test_free_mbuf(Mbuf* mbuf);
extern fn int ff_check_tap_permission(ZString iface, char* err, usz err_len);

<* Wraps rte_strerror as a C3 String (temp-allocated copy). *>
fn String strerror(int errnum) {
	ZString message = rte_strerror(errnum);
	return message.str_view().copy(tmem);
}
